"""
dnssec_resolver.py
==================
Q2 - Recursive DNSSEC-validating resolver.

Implements a full iterative walk:
    Root (.)  ->  TLD (.com / .org / ...)  ->  Authoritative (example.com)

At EVERY hop the Q1 validation module (dnssec_validator.py) is called to:
    * Validate DNSKEY
    * Validate RRSIG
    * Validate DS chain

Public API
----------
resolve(domain, record_type="A") -> ResolverResult
"""

from __future__ import annotations

import sys
import textwrap
from dataclasses import dataclass, field
from typing import List, Optional

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset

# -- Q1 module --
import dnssec_validator as q1
from dnssec_validator import DNSSECResult, _query_with_do, _extract_rrset


# ======================================================================
# Data structures
# ======================================================================

@dataclass
class HopResult:
    """DNSSEC validation outcome for one zone in the resolution path."""
    zone: str
    nameservers: List[str]
    dnskey_valid: bool = False
    rrsig_valid: bool = False
    ds_valid: bool = False
    errors: List[str] = field(default_factory=list)
    info: List[str] = field(default_factory=list)

    @property
    def fully_valid(self) -> bool:
        return self.dnskey_valid and self.rrsig_valid and self.ds_valid

    def summary(self) -> str:
        ok = lambda b: "Y" if b else "N"
        status = "SECURE" if self.fully_valid else "INSECURE/ERROR"
        return (
            f"  Zone : {self.zone}\n"
            f"  NS   : {', '.join(self.nameservers[:2])}{'...' if len(self.nameservers) > 2 else ''}\n"
            f"  DNSKEY {ok(self.dnskey_valid)}  RRSIG {ok(self.rrsig_valid)}  DS {ok(self.ds_valid)}"
            f"  -> {status}"
        )


@dataclass
class ResolverResult:
    """Final answer from the recursive DNSSEC resolver."""
    query_domain: str
    record_type: str
    ip_addresses: List[str] = field(default_factory=list)
    resolution_path: List[str] = field(default_factory=list)
    hops: List[HopResult] = field(default_factory=list)
    dnssec_status: str = "UNKNOWN"
    errors: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        sep = "=" * 64
        thin = "-" * 64

        lines = [
            "",
            sep,
            "  DNSSEC Recursive Resolver - Result",
            sep,
            f"  Query  : {self.query_domain}  IN  {self.record_type}",
        ]

        if self.ip_addresses:
            for ip in self.ip_addresses:
                lines.append(f"  IP     : {ip}")
        else:
            lines.append("  IP     : (none resolved)")

        lines.append(f"  DNSSEC : {self.dnssec_status}")

        if self.resolution_path:
            lines.append(f"\n  Path   : {' -> '.join(self.resolution_path)}")

        if self.hops:
            lines.append(f"\n{thin}")
            lines.append("  Hop-by-Hop DNSSEC Validation")
            lines.append(thin)
            for i, hop in enumerate(self.hops, 1):
                lines.append(f"\n  [{i}] {hop.zone}")
                lines.append(hop.summary())
                if hop.errors:
                    for e in hop.errors:
                        lines.append(f"      x {e}")
                if hop.info:
                    for inf in hop.info[-3:]:
                        lines.append(f"      - {inf}")

        if self.errors:
            lines.append(f"\n{thin}")
            lines.append("  Resolver Errors")
            lines.append(thin)
            for e in self.errors:
                lines.append(f"  x {e}")

        lines.append(f"\n{sep}\n")
        return "\n".join(lines)


# ======================================================================
# Root hint table
# ======================================================================

ROOT_SERVERS: List[str] = [
    "198.41.0.4",
    "199.9.14.201",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
]

_VALIDATING_RESOLVERS = ["8.8.8.8", "1.1.1.1"]


# ======================================================================
# Low-level helpers
# ======================================================================

def _udp_tcp(request: dns.message.Message,
             nameservers: List[str],
             timeout: float = 5.0) -> dns.message.Message:
    last_exc: Exception = RuntimeError("No nameservers provided")
    for ns in nameservers:
        try:
            resp = dns.query.udp(request, ns, timeout=timeout)
            if resp.flags & dns.flags.TC:
                resp = dns.query.tcp(request, ns, timeout=timeout)
            return resp
        except Exception as exc:
            last_exc = exc
    raise last_exc


def _do_query(qname_str: str,
              rdtype: int,
              nameservers: List[str],
              timeout: float = 5.0) -> dns.message.Message:
    qname = dns.name.from_text(qname_str)
    req = dns.message.make_query(qname, rdtype, want_dnssec=True,
                                 use_edns=True, payload=4096)
    return _udp_tcp(req, nameservers, timeout)


def _glue_addresses(msg: dns.message.Message,
                    ns_name: dns.name.Name) -> List[str]:
    addrs: List[str] = []
    for rrset in msg.additional:
        if rrset.name == ns_name and rrset.rdtype in (
                dns.rdatatype.A, dns.rdatatype.AAAA):
            for rr in rrset:
                addrs.append(rr.address)
    return addrs


def _resolve_ns_addresses(ns_name: str) -> List[str]:
    for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
        try:
            msg = _do_query(ns_name, rdtype, _VALIDATING_RESOLVERS)
            rrset = _extract_rrset(msg, ns_name.rstrip("."), rdtype)
            if rrset:
                return [r.address for r in rrset]
        except Exception:
            pass
    return []


# ======================================================================
# Per-zone DNSSEC validation (wraps Q1)
# ======================================================================

def _validate_zone_at_hop(zone_fqdn: str,
                           nameservers: List[str],
                           hop: HopResult) -> None:
    zone = zone_fqdn.rstrip(".")
    if not zone:
        zone_str = "."
    else:
        zone_str = zone

    tmp = DNSSECResult(domain=zone_str if zone_str != "." else ".",
                       record_type="DNSKEY")
    try:
        if zone_str == ".":
            dnskey_rrset, dnskey_rrsigs = q1._fetch_dnskey(tmp, ".")
        else:
            dnskey_rrset, dnskey_rrsigs = q1._fetch_dnskey(tmp, zone_str)
        hop.dnskey_valid = True
        hop.info.append(f"DNSKEY: fetched {len(list(dnskey_rrset))} key(s)")
    except Exception as exc:
        hop.errors.append(f"DNSKEY fetch failed: {exc}")
        return

    rrsig_ok = q1._verify_rrsig_dnskey(tmp, dnskey_rrset, dnskey_rrsigs)
    hop.rrsig_valid = rrsig_ok
    hop.info.extend(tmp.info[-2:])
    if not rrsig_ok:
        hop.errors.extend(tmp.errors)

    if zone_str == ".":
        hop.ds_valid = True
        hop.info.append("DS: root zone uses built-in trust anchor")
    else:
        ds_result = DNSSECResult(domain=zone_str, record_type="DS")
        ds_rrset = q1._fetch_ds(ds_result, zone_str)
        ds_ok = q1._verify_ds(ds_result, dnskey_rrset, ds_rrset)
        hop.ds_valid = ds_ok
        hop.info.extend(ds_result.info[-2:])
        if not ds_ok:
            hop.errors.extend(ds_result.errors[-2:])


# ======================================================================
# Iterative walk:  Root -> TLD -> Authoritative
# ======================================================================

def _iterative_resolve(domain: str,
                       rdtype_int: int,
                       result: ResolverResult) -> Optional[dns.rrset.RRset]:
    qname = dns.name.from_text(domain)
    labels = qname.labels

    zones_to_walk: List[dns.name.Name] = []
    for i in range(len(labels) - 1, -1, -1):
        zone_name = dns.name.Name(labels[i:])
        zones_to_walk.append(zone_name)

    current_ns = ROOT_SERVERS[:]
    answer_rrset: Optional[dns.rrset.RRset] = None

    for zone_name in zones_to_walk:
        zone_fqdn = zone_name.to_text()
        zone_display = zone_fqdn

        hop = HopResult(zone=zone_display, nameservers=current_ns[:3])
        _validate_zone_at_hop(zone_fqdn, current_ns, hop)
        result.hops.append(hop)
        result.resolution_path.append(zone_display)

        try:
            msg = _do_query(domain, rdtype_int, current_ns)
        except Exception as exc:
            result.errors.append(f"Query to {zone_display} NS failed: {exc}")
            break

        rcode = msg.rcode()
        if rcode == dns.rcode.NXDOMAIN:
            result.errors.append(f"NXDOMAIN returned for {domain}")
            break

        ans = _extract_rrset(msg, domain, rdtype_int)
        if ans:
            answer_rrset = ans
            break

        next_ns_names: List[dns.name.Name] = []
        for rrset in msg.authority:
            if rrset.rdtype == dns.rdatatype.NS:
                for rr in rrset:
                    next_ns_names.append(rr.target)
                break

        if not next_ns_names:
            result.errors.append(
                f"No answer and no NS referral from {zone_display}; stopping.")
            break

        next_ns_ips: List[str] = []
        for ns_name in next_ns_names:
            glue = _glue_addresses(msg, ns_name)
            if glue:
                next_ns_ips.extend(glue)
            else:
                resolved = _resolve_ns_addresses(ns_name.to_text())
                next_ns_ips.extend(resolved)
            if len(next_ns_ips) >= 4:
                break

        if not next_ns_ips:
            result.errors.append(
                f"Could not resolve NS addresses for zone below {zone_display}")
            break

        current_ns = next_ns_ips

    return answer_rrset


# ======================================================================
# Public entry point
# ======================================================================

def resolve(domain: str, record_type: str = "A") -> ResolverResult:
    domain = domain.rstrip(".")
    record_type = record_type.upper()
    rdtype_int = dns.rdatatype.from_text(record_type)

    result = ResolverResult(query_domain=domain, record_type=record_type)

    answer_rrset = _iterative_resolve(domain, rdtype_int, result)

    if answer_rrset:
        for rr in answer_rrset:
            if hasattr(rr, "address"):
                result.ip_addresses.append(rr.address)
            else:
                result.ip_addresses.append(str(rr))

    leaf_result = q1.validate(domain, record_type)

    hop_all_valid = all(h.fully_valid for h in result.hops)

    if not result.ip_addresses:
        result.dnssec_status = "INDETERMINATE"
    elif leaf_result.chain_valid and hop_all_valid:
        result.dnssec_status = "VERIFIED"
    elif leaf_result.errors and any(
            "FAILED" in e or "mismatch" in e for e in leaf_result.errors):
        result.dnssec_status = "BOGUS"
    elif result.hops and not hop_all_valid:
        result.dnssec_status = "INSECURE"
    else:
        result.dnssec_status = "INDETERMINATE"

    leaf_hop = HopResult(
        zone=f"{domain}. (leaf - Q1 full chain)",
        nameservers=["8.8.8.8", "1.1.1.1"],
        dnskey_valid=bool(leaf_result.dnskeys),
        rrsig_valid=bool(leaf_result.rrsigs),
        ds_valid=bool(leaf_result.ds_records),
    )
    leaf_hop.info = [l for l in leaf_result.info if l.startswith("✓") or l.startswith("DS") or l.startswith("RRSIG")]
    leaf_hop.errors = leaf_result.errors
    result.hops.append(leaf_hop)
    result.resolution_path.append(f"{domain}. (authoritative)")

    return result


# ======================================================================
# CLI
# ======================================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <domain> [record_type]")
        print(f"       {sys.argv[0]} cloudflare.com A")
        sys.exit(1)

    domain_arg = sys.argv[1]
    rtype_arg  = sys.argv[2] if len(sys.argv) > 2 else "A"

    res = resolve(domain_arg, rtype_arg)
    print(res)

    print("\n-- Q1 Full DNSSEC Report (leaf zone) --")
    leaf = q1.validate(domain_arg, rtype_arg)
    print(leaf)

    sys.exit(0 if res.dnssec_status == "VERIFIED" else 1)
