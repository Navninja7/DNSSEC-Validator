"""
dnssec_validator.py
====================
Reusable DNSSEC validation module.

Public API
----------
validate(domain, record_type) -> DNSSECResult
    Full DNSSEC validation pipeline:
      1. Fetch answer RRset + RRSIG
      2. Fetch DNSKEY RRset + RRSIG
      3. Fetch DS from parent zone
      4. Verify RRSIG(answer)   using DNSKEY   -> chain step 1
      5. Verify RRSIG(DNSKEY)   using DNSKEY   -> self-signed KSK
      6. Verify DS              against DNSKEY  -> chain step 2

DNSSECResult (dataclass)
    .domain          str
    .record_type     str
    .answers         list[dns.rdata.Rdata]
    .dnskeys         list[dns.rdata.Rdata]
    .rrsigs          list[dns.rdata.Rdata]   (for the answer RRset)
    .ds_records      list[dns.rdata.Rdata]
    .chain_valid     bool
    .errors          list[str]
    .info            list[str]               (human-readable log)
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import List

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class DNSSECResult:
    domain: str
    record_type: str
    answers: List[dns.rdata.Rdata] = field(default_factory=list)
    dnskeys: List[dns.rdata.Rdata] = field(default_factory=list)
    rrsigs: List[dns.rdata.Rdata] = field(default_factory=list)   # for answer RRset
    ds_records: List[dns.rdata.Rdata] = field(default_factory=list)
    chain_valid: bool = False
    errors: List[str] = field(default_factory=list)
    info: List[str] = field(default_factory=list)

    # ---- pretty printing ----
    def __str__(self) -> str:
        lines: list[str] = [
            "",
            "=" * 60,
            f"  DNSSEC Validation Report",
            f"  Domain : {self.domain}",
            f"  RRtype : {self.record_type}",
            "=" * 60,
        ]

        # Answer records
        lines.append("\n[Answer Records]")
        if self.answers:
            for r in self.answers:
                lines.append(f"  {r}")
        else:
            lines.append("  (none)")

        # DNSKEY records
        lines.append("\n[DNSKEY Records]")
        if self.dnskeys:
            for r in self.dnskeys:
                flags  = r.flags
                proto  = r.protocol
                algo   = r.algorithm
                tag    = dns.dnssec.key_id(r)
                ktype  = "KSK/SEP" if (flags & 0x0001) else "ZSK"
                lines.append(f"  flags={flags}  protocol={proto}  algorithm={algo}"
                             f"  key_tag={tag}  ({ktype})")
        else:
            lines.append("  (none)")

        # RRSIG records (for the answer RRset)
        lines.append(f"\n[RRSIG Records for {self.record_type}]")
        if self.rrsigs:
            for r in self.rrsigs:
                lines.append(f"  type_covered={dns.rdatatype.to_text(r.type_covered)}"
                             f"  key_tag={r.key_tag}"
                             f"  signer={r.signer}"
                             f"  algo={r.algorithm}")
        else:
            lines.append("  (none)")

        # DS records
        lines.append("\n[DS Records (from parent)]")
        if self.ds_records:
            for r in self.ds_records:
                lines.append(f"  key_tag={r.key_tag}  algorithm={r.algorithm}"
                             f"  digest_type={r.digest_type}"
                             f"  digest={r.digest.hex()[:32]}...")
        else:
            lines.append("  (none)")

        # Validation log
        lines.append("\n[Validation Log]")
        for msg in self.info:
            lines.append(f"  {msg}")

        # Errors
        if self.errors:
            lines.append("\n[Errors]")
            for e in self.errors:
                lines.append(f"  x {e}")

        # Final verdict
        verdict = "CHAIN VALID - DNSSEC fully validated" if self.chain_valid \
                  else "CHAIN INVALID - see errors above"
        lines.append(f"\n{'=' * 60}")
        lines.append(f"  VERDICT: {verdict}")
        lines.append("=" * 60 + "\n")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Use Google & Cloudflare as DNSSEC-validating resolvers (DO bit respected)
_RESOLVERS = ["8.8.8.8", "1.1.1.1"]


def _make_resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = _RESOLVERS
    r.timeout = 5
    r.lifetime = 10
    return r


def _query_with_do(name: str, rdtype: int,
                   nameservers: list[str] = _RESOLVERS) -> dns.message.Message:
    """
    Send a query with the DO (DNSSEC OK) bit set.
    Returns the raw DNS Message (not filtered by the stub resolver).
    """
    qname = dns.name.from_text(name)
    request = dns.message.make_query(qname, rdtype,
                                     want_dnssec=True,
                                     use_edns=True,
                                     payload=4096)
    last_err: Exception | None = None
    for ns in nameservers:
        try:
            response = dns.query.udp(request, ns, timeout=5)
            if response.flags & dns.flags.TC:          # truncated -> retry TCP
                response = dns.query.tcp(request, ns, timeout=5)
            return response
        except Exception as exc:
            last_err = exc
    raise RuntimeError(f"All nameservers failed for {name}/{dns.rdatatype.to_text(rdtype)}: "
                       f"{last_err}")


def _extract_rrset(msg: dns.message.Message,
                   name: str,
                   rdtype: int) -> dns.rrset.RRset | None:
    """Pull an RRset of the given type from all sections of a DNS message."""
    qname = dns.name.from_text(name)
    for section in (msg.answer, msg.authority, msg.additional):
        for rrset in section:
            if rrset.name == qname and rrset.rdtype == rdtype:
                return rrset
    return None


_DIGEST_TYPE_MAP = {1: "SHA1", 2: "SHA256", 4: "SHA384"}


def _key_id(dnskey_rdata: dns.rdata.Rdata) -> int:
    """Compute the key tag (RFC 4034 Appendix B)."""
    return dns.dnssec.key_id(dnskey_rdata)


def _compute_ds_digest(dnskey_rdata: dns.rdata.Rdata,
                        owner: dns.name.Name,
                        digest_type: int) -> bytes:
    """
    Compute DS digest using dnspython's make_ds helper.
    """
    algo_name = _DIGEST_TYPE_MAP.get(digest_type)
    if algo_name is None:
        raise ValueError(f"Unsupported DS digest type: {digest_type}")
    ds_rr = dns.dnssec.make_ds(owner, dnskey_rdata, algo_name)
    return ds_rr.digest


# ---------------------------------------------------------------------------
# Step 1 - Fetch records
# ---------------------------------------------------------------------------

def _fetch_answer(result: DNSSECResult, domain: str, rdtype_int: int) -> tuple:
    """Returns (answer_rrset, rrsig_rrset) or raises."""
    msg = _query_with_do(domain, rdtype_int)
    rdtype_text = dns.rdatatype.to_text(rdtype_int)

    answer_rrset = _extract_rrset(msg, domain, rdtype_int)
    rrsig_rrset  = _extract_rrset(msg, domain, dns.rdatatype.RRSIG)

    if answer_rrset is None:
        raise LookupError(f"No {rdtype_text} records found for {domain}")

    result.answers = list(answer_rrset)
    result.info.append(f"Fetched {len(result.answers)} {rdtype_text} record(s) for {domain}")

    if rrsig_rrset:
        result.rrsigs = [r for r in rrsig_rrset
                         if r.type_covered == rdtype_int]
        result.info.append(f"Fetched {len(result.rrsigs)} RRSIG(s) covering {rdtype_text}")
    else:
        result.info.append(f"No RRSIG found for {rdtype_text} - zone may not be signed")

    return answer_rrset, rrsig_rrset


def _fetch_dnskey(result: DNSSECResult, domain: str) -> tuple:
    """Returns (dnskey_rrset, dnskey_rrsig_rrset)."""
    msg = _query_with_do(domain, dns.rdatatype.DNSKEY)

    dnskey_rrset = _extract_rrset(msg, domain, dns.rdatatype.DNSKEY)
    dnskey_rrsig = _extract_rrset(msg, domain, dns.rdatatype.RRSIG)

    if dnskey_rrset is None:
        raise LookupError(f"No DNSKEY records found for {domain}")

    result.dnskeys = list(dnskey_rrset)
    result.info.append(f"Fetched {len(result.dnskeys)} DNSKEY record(s)")

    dnskey_rrsigs = []
    if dnskey_rrsig:
        dnskey_rrsigs = [r for r in dnskey_rrsig
                         if r.type_covered == dns.rdatatype.DNSKEY]
        result.info.append(f"Fetched {len(dnskey_rrsigs)} RRSIG(s) covering DNSKEY")

    return dnskey_rrset, dnskey_rrsigs


def _fetch_ds(result: DNSSECResult, domain: str) -> dns.rrset.RRset | None:
    """Fetch DS records from the parent zone."""
    try:
        msg = _query_with_do(domain, dns.rdatatype.DS)
        ds_rrset = _extract_rrset(msg, domain, dns.rdatatype.DS)
        if ds_rrset:
            result.ds_records = list(ds_rrset)
            result.info.append(f"Fetched {len(result.ds_records)} DS record(s) from parent")
        else:
            result.info.append("No DS records found in parent zone (unsigned delegation?)")
        return ds_rrset
    except Exception as exc:
        result.info.append(f"DS lookup failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# Step 2 - Verify RRSIG(answer) using DNSKEY   [chain step 1]
# ---------------------------------------------------------------------------

def _verify_rrsig_answer(result: DNSSECResult,
                          answer_rrset: dns.rrset.RRset,
                          dnskey_rrset: dns.rrset.RRset,
                          rrsig_rrset: dns.rrset.RRset | None) -> bool:
    if not rrsig_rrset:
        result.errors.append("Cannot verify answer: no RRSIG present")
        return False
    if not dnskey_rrset:
        result.errors.append("Cannot verify answer: no DNSKEY present")
        return False

    keys = {dnskey_rrset.name: dnskey_rrset}
    try:
        dns.dnssec.validate(answer_rrset, rrsig_rrset, keys)
        result.info.append("RRSIG(answer) verified successfully using DNSKEY")
        return True
    except dns.dnssec.ValidationFailure as exc:
        result.errors.append(f"RRSIG(answer) validation FAILED: {exc}")
        return False
    except Exception as exc:
        result.errors.append(f"Unexpected error verifying RRSIG(answer): {exc}")
        return False


# ---------------------------------------------------------------------------
# Step 3 - Verify RRSIG(DNSKEY) using DNSKEY   [self-signed KSK]
# ---------------------------------------------------------------------------

def _verify_rrsig_dnskey(result: DNSSECResult,
                          dnskey_rrset: dns.rrset.RRset,
                          dnskey_rrsigs: list) -> bool:
    if not dnskey_rrsigs:
        result.errors.append("Cannot verify DNSKEY: no RRSIG(DNSKEY) present")
        return False

    rrsig_rrset = dns.rrset.RRset(dnskey_rrset.name, dns.rdataclass.IN, dns.rdatatype.RRSIG)
    for r in dnskey_rrsigs:
        rrsig_rrset.add(r)

    keys = {dnskey_rrset.name: dnskey_rrset}
    try:
        dns.dnssec.validate(dnskey_rrset, rrsig_rrset, keys)
        result.info.append("RRSIG(DNSKEY) verified - KSK self-signature is valid")
        return True
    except dns.dnssec.ValidationFailure as exc:
        result.errors.append(f"RRSIG(DNSKEY) validation FAILED: {exc}")
        return False
    except Exception as exc:
        result.errors.append(f"Unexpected error verifying RRSIG(DNSKEY): {exc}")
        return False


# ---------------------------------------------------------------------------
# Step 4 - Verify DS matches a DNSKEY            [chain step 2]
# ---------------------------------------------------------------------------

def _verify_ds(result: DNSSECResult,
               dnskey_rrset: dns.rrset.RRset,
               ds_rrset: dns.rrset.RRset | None) -> bool:
    if ds_rrset is None:
        result.errors.append("Cannot verify DS: no DS records from parent")
        return False

    owner = dnskey_rrset.name
    for ds in ds_rrset:
        for dnskey in dnskey_rrset:
            tag = dns.dnssec.key_id(dnskey)
            if tag != ds.key_tag:
                continue
            if dnskey.algorithm != ds.algorithm:
                continue
            try:
                computed = _compute_ds_digest(dnskey, owner, ds.digest_type)
                if computed == ds.digest:
                    result.info.append(
                        f"DS(key_tag={ds.key_tag}, digest_type={ds.digest_type}) "
                        f"matches DNSKEY - trust chain established"
                    )
                    return True
                else:
                    result.errors.append(
                        f"DS(key_tag={ds.key_tag}) digest mismatch - "
                        f"expected {ds.digest.hex()}, got {computed.hex()}"
                    )
            except ValueError as exc:
                result.errors.append(f"DS digest computation error: {exc}")

    result.errors.append(
        "No DS record matched any DNSKEY (key_tag, algorithm, or digest mismatch)"
    )
    return False


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def validate(domain: str, record_type: str = "A") -> DNSSECResult:
    """
    Perform full DNSSEC validation for *domain* / *record_type*.
    """
    domain = domain.rstrip(".")
    record_type = record_type.upper()
    rdtype_int = dns.rdatatype.from_text(record_type)

    result = DNSSECResult(domain=domain, record_type=record_type)
    result.info.append(f"Starting DNSSEC validation: {domain}  IN  {record_type}")

    step1_ok = step2_ok = step3_ok = step4_ok = False

    try:
        answer_rrset, rrsig_rrset = _fetch_answer(result, domain, rdtype_int)
        dnskey_rrset, dnskey_rrsigs = _fetch_dnskey(result, domain)
        ds_rrset = _fetch_ds(result, domain)
        step1_ok = True
    except LookupError as exc:
        result.errors.append(f"Record fetch failed: {exc}")
        return result
    except Exception as exc:
        result.errors.append(f"Unexpected fetch error: {exc}")
        return result

    answer_rrsig_rrset = None
    if rrsig_rrset and result.rrsigs:
        answer_rrsig_rrset = dns.rrset.RRset(
            dns.name.from_text(domain), dns.rdataclass.IN, dns.rdatatype.RRSIG
        )
        for r in result.rrsigs:
            answer_rrsig_rrset.add(r)

    result.info.append("-- Step 1: Verify RRSIG(answer) using DNSKEY --")
    step2_ok = _verify_rrsig_answer(result, answer_rrset, dnskey_rrset, answer_rrsig_rrset)

    result.info.append("-- Step 2: Verify RRSIG(DNSKEY) using DNSKEY --")
    step3_ok = _verify_rrsig_dnskey(result, dnskey_rrset, dnskey_rrsigs)

    result.info.append("-- Step 3: Verify DS(parent) against DNSKEY --")
    step4_ok = _verify_ds(result, dnskey_rrset, ds_rrset)

    result.chain_valid = step2_ok and step3_ok and step4_ok
    return result


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <domain> [record_type]")
        print(f"       {sys.argv[0]} cloudflare.com A")
        sys.exit(1)

    domain_arg = sys.argv[1]
    rtype_arg  = sys.argv[2] if len(sys.argv) > 2 else "A"

    res = validate(domain_arg, rtype_arg)
    print(res)
    sys.exit(0 if res.chain_valid else 1)
