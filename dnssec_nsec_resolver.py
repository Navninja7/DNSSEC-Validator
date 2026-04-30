"""
dnssec_nsec_resolver.py
========================
Q3 – Extends the Q2 recursive resolver to handle non-existent
domains and record types securely using NSEC / NSEC3 proof-of-
non-existence.

Modifications over Q2
---------------------
1.  Detect NXDOMAIN (domain does not exist) and NODATA (record type
    does not exist for an existing domain).
2.  Retrieve NSEC or NSEC3 records (and their covering RRSIGs) from
    the authority section of the DNS response.
3.  Validate:
    a. The RRSIG over the NSEC/NSEC3 record (reuses Q1 module).
    b. That the NSEC/NSEC3 range actually *covers* (proves the absence
       of) the queried name or type.

Public API
----------
resolve_with_nsec(domain, record_type="A") -> NsecResolverResult

Dependencies
------------
- dnssec_validator  (Q1)
- dnssec_resolver   (Q2)
- dnspython >= 2.4
"""

from __future__ import annotations

import hashlib
import struct
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import dns.dnssec
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

# ── Q1 and Q2 imports ─────────────────────────────────────────────────────
import dnssec_validator as q1
from dnssec_validator import DNSSECResult, _query_with_do, _extract_rrset
import dnssec_resolver as q2
from dnssec_resolver import (
    HopResult,
    ResolverResult,
    ROOT_SERVERS,
    _do_query,
    _validate_zone_at_hop,
)


# ══════════════════════════════════════════════════════════════════════════
# Data structures
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class NsecProof:
    """Represents one NSEC or NSEC3 record used as denial proof."""
    proof_type: str             # "NSEC" or "NSEC3"
    owner: str                  # owner name of the NSEC/NSEC3 RR
    next_name: str = ""         # NSEC: next domain name in canonical order
    type_bitmap: List[str] = field(default_factory=list)  # RR types present at owner
    # NSEC3-specific
    hash_algo: int = 0
    iterations: int = 0
    salt: str = ""
    hashed_next: str = ""       # base32-encoded next hashed owner
    rrsig_valid: bool = False
    covers_query: bool = False  # True if this proof covers the queried name/type
    info: List[str] = field(default_factory=list)

    def summary(self) -> str:
        status = "VALID" if (self.rrsig_valid and self.covers_query) else "INVALID"
        lines = [f"    {self.proof_type} Proof [{status}]"]
        lines.append(f"      Owner     : {self.owner}")
        if self.proof_type == "NSEC":
            lines.append(f"      Next      : {self.next_name}")
        else:
            lines.append(f"      Hash algo : {self.hash_algo}  iterations={self.iterations}")
            lines.append(f"      Next hash : {self.hashed_next}")
        lines.append(f"      Types     : {', '.join(self.type_bitmap[:10])}"
                      f"{'...' if len(self.type_bitmap) > 10 else ''}")
        lines.append(f"      RRSIG ok  : {self.rrsig_valid}")
        lines.append(f"      Covers Q  : {self.covers_query}")
        for i in self.info:
            lines.append(f"      - {i}")
        return "\n".join(lines)


@dataclass
class NsecResolverResult:
    """Extended resolver result that includes NSEC/NSEC3 proof information."""
    query_domain: str
    record_type: str
    existence: str = "EXISTS"        # "EXISTS" | "NXDOMAIN" | "NODATA"
    ip_addresses: List[str] = field(default_factory=list)
    resolution_path: List[str] = field(default_factory=list)
    hops: List[HopResult] = field(default_factory=list)
    dnssec_status: str = "UNKNOWN"   # "VERIFIED" | "INSECURE" | "BOGUS"
    nsec_proofs: List[NsecProof] = field(default_factory=list)
    nsec_proof_valid: bool = False   # overall denial proof validity
    errors: List[str] = field(default_factory=list)
    info: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        sep = "=" * 64
        thin = "-" * 64

        lines = [
            "",
            sep,
            "  DNSSEC Resolver with NSEC/NSEC3 – Result",
            sep,
            f"  Query    : {self.query_domain}  IN  {self.record_type}",
            f"  Result   : {self.existence}",
        ]

        if self.existence == "EXISTS" and self.ip_addresses:
            for ip in self.ip_addresses:
                lines.append(f"  IP       : {ip}")

        lines.append(f"  DNSSEC   : {self.dnssec_status}")

        if self.resolution_path:
            lines.append(f"\n  Path     : {' -> '.join(self.resolution_path)}")

        # NSEC / NSEC3 proof details
        if self.nsec_proofs:
            proof_verdict = "VALID" if self.nsec_proof_valid else "INVALID"
            lines.append(f"\n{thin}")
            lines.append(f"  Denial-of-Existence Proof: {proof_verdict}")
            lines.append(thin)
            for p in self.nsec_proofs:
                lines.append(p.summary())

        # Hop detail
        if self.hops:
            lines.append(f"\n{thin}")
            lines.append("  Hop-by-Hop DNSSEC Validation")
            lines.append(thin)
            for i, hop in enumerate(self.hops, 1):
                lines.append(f"\n  [{i}] {hop.zone}")
                lines.append(hop.summary())

        # Info log
        if self.info:
            lines.append(f"\n{thin}")
            lines.append("  Resolution Log")
            lines.append(thin)
            for msg in self.info:
                lines.append(f"  {msg}")

        # Errors
        if self.errors:
            lines.append(f"\n{thin}")
            lines.append("  Errors")
            lines.append(thin)
            for e in self.errors:
                lines.append(f"  x {e}")

        lines.append(f"\n{sep}\n")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════
# NSEC helpers
# ══════════════════════════════════════════════════════════════════════════

def _canonical_order(name: dns.name.Name) -> dns.name.Name:
    """Return the DNSSEC canonical (lowercased) form of a dns.name.Name."""
    return name.canonicalize()


def _name_in_nsec_range(query_name: dns.name.Name,
                        nsec_owner: dns.name.Name,
                        nsec_next: dns.name.Name) -> bool:
    """
    Check whether *query_name* falls within the open interval
    (nsec_owner, nsec_next) in canonical DNS name ordering.

    This covers the normal case.  The "last NSEC wraps around" case
    (nsec_owner > nsec_next) is also handled: the query name is covered
    if it is > nsec_owner  OR  < nsec_next.
    """
    qc = _canonical_order(query_name)
    oc = _canonical_order(nsec_owner)
    nc = _canonical_order(nsec_next)

    if oc < nc:
        # Normal range
        return oc < qc < nc
    else:
        # Wrap-around (last NSEC in zone)
        return qc > oc or qc < nc


def _rdtype_text_list(nsec_rdata) -> List[str]:
    """Extract the type-bitmap from an NSEC or NSEC3 rdata as text list."""
    # dnspython stores windows as list of (window, bitmap) tuples
    types: List[str] = []
    if hasattr(nsec_rdata, 'windows'):
        for window, bitmap in nsec_rdata.windows:
            for i, byte_val in enumerate(bitmap):
                for bit in range(8):
                    if byte_val & (0x80 >> bit):
                        rdtype_num = window * 256 + i * 8 + bit
                        try:
                            types.append(dns.rdatatype.to_text(rdtype_num))
                        except Exception:
                            types.append(str(rdtype_num))
    return types


def _verify_nsec_rrsig(nsec_rrset: dns.rrset.RRset,
                        rrsig_rrset: dns.rrset.RRset | None,
                        dnskey_rrset: dns.rrset.RRset | None) -> bool:
    """Verify the RRSIG covering an NSEC/NSEC3 rrset using the zone DNSKEY."""
    if not rrsig_rrset or not dnskey_rrset:
        return False
    keys = {dnskey_rrset.name: dnskey_rrset}
    try:
        dns.dnssec.validate(nsec_rrset, rrsig_rrset, keys)
        return True
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════
# NSEC3 helpers
# ══════════════════════════════════════════════════════════════════════════

def _nsec3_hash(name: dns.name.Name,
                algorithm: int,
                salt: bytes,
                iterations: int) -> str:
    """
    Compute the NSEC3 hash of *name* per RFC 5155 §5.

    Returns uppercase base32hex-encoded hash (no padding).

    Algorithm 1 = SHA-1 (the only one defined so far).
    """
    if algorithm != 1:
        raise ValueError(f"Unsupported NSEC3 hash algorithm: {algorithm}")

    # Wire-format of the canonical owner name
    wire = name.canonicalize().to_wire()

    # Initial hash: H(name || salt)
    digest = hashlib.sha1(wire + salt).digest()

    # Additional iterations
    for _ in range(iterations):
        digest = hashlib.sha1(digest + salt).digest()

    # Encode as base32hex (RFC 4648 §7), uppercase, no padding
    import base64
    return base64.b32encode(digest).decode("ascii").upper().rstrip("=")


def _hash_in_nsec3_range(query_hash: str,
                          nsec3_owner_hash: str,
                          nsec3_next_hash: str) -> bool:
    """
    Check if a hashed name falls in the (owner_hash, next_hash) range.
    All hashes are uppercase base32hex strings.
    Handles wrap-around just like NSEC.
    """
    qh = query_hash.upper()
    oh = nsec3_owner_hash.upper()
    nh = nsec3_next_hash.upper()

    if oh < nh:
        return oh < qh < nh
    else:
        return qh > oh or qh < nh


# ══════════════════════════════════════════════════════════════════════════
# Core: Extract and validate NSEC/NSEC3 from a DNS response
# ══════════════════════════════════════════════════════════════════════════

def _extract_nsec_proofs(msg: dns.message.Message,
                          query_name: str,
                          query_rdtype: int,
                          zone_name: str) -> List[NsecProof]:
    """
    Walk the authority section of *msg* looking for NSEC or NSEC3 records.
    For each one found, build an NsecProof object and check coverage.
    """
    qname = dns.name.from_text(query_name)
    proofs: List[NsecProof] = []

    # Collect all NSEC / NSEC3 rrsets and their RRSIGs from authority
    nsec_rrsets: List[Tuple[dns.rrset.RRset, Optional[dns.rrset.RRset]]] = []

    # Group authority RRsets by (name, rdtype)
    authority_map: dict[Tuple[dns.name.Name, int], dns.rrset.RRset] = {}
    for rrset in msg.authority:
        key = (rrset.name, rrset.rdtype)
        authority_map[key] = rrset

    # Find NSEC records
    for (name, rdtype), rrset in authority_map.items():
        if rdtype == dns.rdatatype.NSEC:
            rrsig_key = (name, dns.rdatatype.RRSIG)
            rrsig_rrset = authority_map.get(rrsig_key)
            nsec_rrsets.append((rrset, rrsig_rrset))

    # Find NSEC3 records
    for (name, rdtype), rrset in authority_map.items():
        if rdtype == dns.rdatatype.NSEC3:
            rrsig_key = (name, dns.rdatatype.RRSIG)
            rrsig_rrset = authority_map.get(rrsig_key)
            nsec_rrsets.append((rrset, rrsig_rrset))

    # Fetch DNSKEY for the zone to verify RRSIGs
    dnskey_rrset = None
    try:
        tmp = DNSSECResult(domain=zone_name, record_type="DNSKEY")
        dnskey_rrset, _ = q1._fetch_dnskey(tmp, zone_name)
    except Exception:
        pass

    for nsec_rrset, rrsig_rrset in nsec_rrsets:
        for rdata in nsec_rrset:
            proof = NsecProof(owner=nsec_rrset.name.to_text())

            if nsec_rrset.rdtype == dns.rdatatype.NSEC:
                # ── NSEC ──────────────────────────────────────────────
                proof.proof_type = "NSEC"
                proof.next_name = rdata.next.to_text()
                proof.type_bitmap = _rdtype_text_list(rdata)

                # Verify RRSIG
                if rrsig_rrset and dnskey_rrset:
                    # Filter RRSIG covering NSEC
                    filtered = dns.rrset.RRset(nsec_rrset.name,
                                               dns.rdataclass.IN,
                                               dns.rdatatype.RRSIG)
                    for sig in rrsig_rrset:
                        if hasattr(sig, 'type_covered') and sig.type_covered == dns.rdatatype.NSEC:
                            filtered.add(sig)
                    if len(filtered) > 0:
                        proof.rrsig_valid = _verify_nsec_rrsig(
                            nsec_rrset, filtered, dnskey_rrset)

                # Check coverage
                nsec_owner = nsec_rrset.name
                nsec_next = rdata.next

                # Case 1: NXDOMAIN – query name falls in the gap
                if _name_in_nsec_range(qname, nsec_owner, nsec_next):
                    proof.covers_query = True
                    proof.info.append(
                        f"Query name {query_name} is in range "
                        f"({nsec_owner.to_text()}, {nsec_next.to_text()}) "
                        f"-> NXDOMAIN proven")

                # Case 2: NODATA – owner matches but type not in bitmap
                if nsec_owner == qname or _canonical_order(nsec_owner) == _canonical_order(qname):
                    rdtype_text = dns.rdatatype.to_text(query_rdtype)
                    if rdtype_text not in proof.type_bitmap:
                        proof.covers_query = True
                        proof.info.append(
                            f"Owner matches query name but {rdtype_text} "
                            f"not in type bitmap -> NODATA proven")

            elif nsec_rrset.rdtype == dns.rdatatype.NSEC3:
                # ── NSEC3 ─────────────────────────────────────────────
                proof.proof_type = "NSEC3"
                proof.hash_algo = rdata.algorithm
                proof.iterations = rdata.iterations
                proof.salt = rdata.salt.hex() if rdata.salt else ""
                # next field in NSEC3 is the hashed next owner name
                import base64
                proof.hashed_next = base64.b32encode(rdata.next).decode().upper().rstrip("=")
                proof.type_bitmap = _rdtype_text_list(rdata)

                # Verify RRSIG
                if rrsig_rrset and dnskey_rrset:
                    filtered = dns.rrset.RRset(nsec_rrset.name,
                                               dns.rdataclass.IN,
                                               dns.rdatatype.RRSIG)
                    for sig in rrsig_rrset:
                        if hasattr(sig, 'type_covered') and sig.type_covered == dns.rdatatype.NSEC3:
                            filtered.add(sig)
                    if len(filtered) > 0:
                        proof.rrsig_valid = _verify_nsec_rrsig(
                            nsec_rrset, filtered, dnskey_rrset)

                # Check coverage: compute the NSEC3 hash of the query name
                try:
                    query_hash = _nsec3_hash(
                        qname, rdata.algorithm, rdata.salt, rdata.iterations)
                    # The owner label of the NSEC3 RR is the hash
                    owner_hash = nsec_rrset.name.labels[0].decode().upper()

                    # Case 1: NXDOMAIN – hash falls in the gap
                    if _hash_in_nsec3_range(query_hash, owner_hash, proof.hashed_next):
                        proof.covers_query = True
                        proof.info.append(
                            f"H({query_name}) = {query_hash} is in range "
                            f"({owner_hash}, {proof.hashed_next}) "
                            f"-> NXDOMAIN proven (NSEC3)")

                    # Case 2: NODATA – hash matches owner
                    if query_hash == owner_hash:
                        rdtype_text = dns.rdatatype.to_text(query_rdtype)
                        if rdtype_text not in proof.type_bitmap:
                            proof.covers_query = True
                            proof.info.append(
                                f"H({query_name}) matches NSEC3 owner but "
                                f"{rdtype_text} not in bitmap -> NODATA proven")
                except Exception as exc:
                    proof.info.append(f"NSEC3 hash computation failed: {exc}")

            proofs.append(proof)

    return proofs


# ══════════════════════════════════════════════════════════════════════════
# Extended iterative resolver with NSEC/NSEC3 awareness
# ══════════════════════════════════════════════════════════════════════════

def resolve_with_nsec(domain: str, record_type: str = "A") -> NsecResolverResult:
    """
    Recursively resolve *domain* / *record_type* starting from the root.
    If the domain or record type does not exist, extract and validate
    NSEC/NSEC3 proof-of-nonexistence.
    """
    domain = domain.rstrip(".")
    record_type = record_type.upper()
    rdtype_int = dns.rdatatype.from_text(record_type)

    result = NsecResolverResult(query_domain=domain, record_type=record_type)
    result.info.append(f"Starting NSEC-aware resolution: {domain} IN {record_type}")

    # ── Phase 1: Standard iterative resolution (reuses Q2 logic) ──────────
    qname = dns.name.from_text(domain)
    labels = qname.labels

    zones_to_walk: List[dns.name.Name] = []
    for i in range(len(labels) - 1, -1, -1):
        zone_name = dns.name.Name(labels[i:])
        zones_to_walk.append(zone_name)

    current_ns = ROOT_SERVERS[:]
    answer_rrset = None
    final_msg: Optional[dns.message.Message] = None
    final_zone: str = ""

    for zone_name in zones_to_walk:
        zone_fqdn = zone_name.to_text()

        # Validate DNSSEC at this hop
        hop = HopResult(zone=zone_fqdn, nameservers=current_ns[:3])
        _validate_zone_at_hop(zone_fqdn, current_ns, hop)
        result.hops.append(hop)
        result.resolution_path.append(zone_fqdn)

        try:
            msg = _do_query(domain, rdtype_int, current_ns)
        except Exception as exc:
            result.errors.append(f"Query to {zone_fqdn} NS failed: {exc}")
            break

        rcode = msg.rcode()
        final_msg = msg
        final_zone = zone_fqdn.rstrip(".")

        # ── NXDOMAIN ──────────────────────────────────────────────────────
        if rcode == dns.rcode.NXDOMAIN:
            result.existence = "NXDOMAIN"
            result.info.append(f"NXDOMAIN received from {zone_fqdn}")

            # Extract and validate NSEC/NSEC3 proofs
            proofs = _extract_nsec_proofs(
                msg, domain, rdtype_int,
                final_zone if final_zone else ".")
            result.nsec_proofs = proofs
            result.nsec_proof_valid = (
                len(proofs) > 0
                and any(p.covers_query for p in proofs)
                and any(p.rrsig_valid for p in proofs)
            )
            break

        # ── Check for answer ──────────────────────────────────────────────
        ans = _extract_rrset(msg, domain, rdtype_int)
        if ans:
            answer_rrset = ans
            result.existence = "EXISTS"
            break

        # ── NODATA: NOERROR but no answer and no referral for target ──────
        # Check if we're at the authoritative zone and got no answer
        has_referral = False
        next_ns_names: List[dns.name.Name] = []
        for rrset in msg.authority:
            if rrset.rdtype == dns.rdatatype.NS:
                for rr in rrset:
                    next_ns_names.append(rr.target)
                has_referral = True
                break

        if not has_referral and rcode == dns.rcode.NOERROR:
            # This is NODATA – the name exists but the record type doesn't
            result.existence = "NODATA"
            result.info.append(
                f"NODATA: {domain} exists but no {record_type} records")

            proofs = _extract_nsec_proofs(
                msg, domain, rdtype_int,
                final_zone if final_zone else ".")
            result.nsec_proofs = proofs
            result.nsec_proof_valid = (
                len(proofs) > 0
                and any(p.covers_query for p in proofs)
                and any(p.rrsig_valid for p in proofs)
            )
            break

        if not next_ns_names:
            result.errors.append(f"No answer and no NS referral from {zone_fqdn}")
            break

        # Follow referral
        next_ns_ips: List[str] = []
        for ns_name in next_ns_names:
            from dnssec_resolver import _glue_addresses, _resolve_ns_addresses
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
                f"Could not resolve NS addresses below {zone_fqdn}")
            break
        current_ns = next_ns_ips

    # ── Phase 2: Populate answer if it exists ─────────────────────────────
    if answer_rrset:
        for rr in answer_rrset:
            if hasattr(rr, "address"):
                result.ip_addresses.append(rr.address)
            else:
                result.ip_addresses.append(str(rr))

    # ── Phase 3: Final DNSSEC status ──────────────────────────────────────
    hop_all_valid = all(h.fully_valid for h in result.hops)

    if result.existence == "EXISTS":
        leaf = q1.validate(domain, record_type)
        if leaf.chain_valid and hop_all_valid:
            result.dnssec_status = "VERIFIED"
        elif leaf.errors:
            result.dnssec_status = "BOGUS"
        else:
            result.dnssec_status = "INSECURE"
    elif result.existence in ("NXDOMAIN", "NODATA"):
        if result.nsec_proof_valid and hop_all_valid:
            result.dnssec_status = "VERIFIED"
            result.info.append(
                "Denial-of-existence cryptographically proven via "
                f"{result.nsec_proofs[0].proof_type if result.nsec_proofs else 'NSEC/NSEC3'}")
        elif result.nsec_proofs and not result.nsec_proof_valid:
            result.dnssec_status = "BOGUS"
            result.info.append("NSEC/NSEC3 proof present but validation failed")
        else:
            result.dnssec_status = "INSECURE"
            result.info.append("No NSEC/NSEC3 proof – zone may not be signed")

    return result


# ══════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <domain> [record_type]")
        print()
        print("Examples:")
        print(f"  {sys.argv[0]} nonexistent.cloudflare.com A      # NXDOMAIN")
        print(f"  {sys.argv[0]} cloudflare.com  TXT                # EXISTS")
        print(f"  {sys.argv[0]} example.com     LOC                # NODATA")
        sys.exit(1)

    domain_arg = sys.argv[1]
    rtype_arg  = sys.argv[2] if len(sys.argv) > 2 else "A"

    res = resolve_with_nsec(domain_arg, rtype_arg)
    print(res)

    sys.exit(0 if res.dnssec_status == "VERIFIED" else 1)
