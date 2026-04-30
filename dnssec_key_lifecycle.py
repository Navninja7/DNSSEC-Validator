"""
dnssec_key_lifecycle.py
========================
Q4 – Analyze real-world DNSSEC key lifecycle.

Uses the Q1 validator and Q2 resolver to retrieve DNSKEY, RRSIG, and DS
records, then detects:
    • Multiple KSKs / ZSKs (indicating a rollover)
    • Old/new key coexistence
    • DS ↔ DNSKEY mismatches (DS pointing to a key that isn't published,
      or a published KSK with no matching DS)
    • Key timing: RRSIG inception/expiration to infer rollover windows

Public API
----------
analyze_key_lifecycle(domain) -> KeyLifecycleReport

Dependencies
------------
- dnssec_validator  (Q1)
- dnspython >= 2.4
"""

from __future__ import annotations

import datetime
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

# ── Q1 module ──────────────────────────────────────────────────────────────
import dnssec_validator as q1
from dnssec_validator import _query_with_do, _extract_rrset, _compute_ds_digest


# ══════════════════════════════════════════════════════════════════════════
# Data structures
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class KeyInfo:
    """Parsed metadata for a single DNSKEY record."""
    key_tag: int
    flags: int
    algorithm: int
    protocol: int
    key_type: str             # "KSK" or "ZSK"
    key_length_bits: int = 0
    has_matching_ds: bool = False   # DS in parent matches this key
    is_signing_dnskey: bool = False # An RRSIG(DNSKEY) uses this key_tag
    is_signing_zone: bool = False   # An RRSIG(A/AAAA/etc.) uses this key_tag
    rrsig_inception: Optional[datetime.datetime] = None
    rrsig_expiration: Optional[datetime.datetime] = None

    def summary(self) -> str:
        ds_mark = "DS-matched" if self.has_matching_ds else "no DS"
        sign_roles = []
        if self.is_signing_dnskey:
            sign_roles.append("signs DNSKEY")
        if self.is_signing_zone:
            sign_roles.append("signs zone data")
        sign_str = ", ".join(sign_roles) if sign_roles else "not actively signing"

        lines = [
            f"    key_tag={self.key_tag}  type={self.key_type}  "
            f"algo={self.algorithm}  flags={self.flags}",
            f"      {ds_mark}  |  {sign_str}",
        ]
        if self.rrsig_inception and self.rrsig_expiration:
            lines.append(
                f"      RRSIG window: {self.rrsig_inception.isoformat()} "
                f"-> {self.rrsig_expiration.isoformat()}")
        return "\n".join(lines)


@dataclass
class KeyLifecycleReport:
    """Complete analysis of a domain's DNSSEC key lifecycle."""
    domain: str
    status: str = "UNKNOWN"   # "STABLE" | "KSK_ROLLOVER" | "ZSK_ROLLOVER"
                              # | "DOUBLE_ROLLOVER" | "DS_MISMATCH" | "NOT_SIGNED"
    keys: List[KeyInfo] = field(default_factory=list)
    ds_key_tags: List[int] = field(default_factory=list)   # key_tags from DS
    observations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    # Counts
    num_ksks: int = 0
    num_zsks: int = 0
    num_ds: int = 0

    def __str__(self) -> str:
        sep = "=" * 64
        thin = "-" * 64

        lines = [
            "",
            sep,
            "  DNSSEC Key Lifecycle Analysis",
            sep,
            f"  Domain : {self.domain}",
            f"  Status : {self.status}",
            f"  Keys   : {self.num_ksks} KSK(s), {self.num_zsks} ZSK(s), "
            f"{self.num_ds} DS record(s)",
            "",
        ]

        # Key details
        lines.append(f"{thin}")
        lines.append("  DNSKEY Records")
        lines.append(thin)
        for k in self.keys:
            lines.append(k.summary())
            lines.append("")

        # DS records
        lines.append(f"{thin}")
        lines.append("  DS Key Tags from Parent")
        lines.append(thin)
        if self.ds_key_tags:
            lines.append(f"    {self.ds_key_tags}")
        else:
            lines.append("    (none)")
        lines.append("")

        # Observations
        lines.append(f"{thin}")
        lines.append("  Observations")
        lines.append(thin)
        for obs in self.observations:
            lines.append(f"  - {obs}")
        if not self.observations:
            lines.append("    (none)")

        # Warnings
        if self.warnings:
            lines.append(f"\n{thin}")
            lines.append("  Warnings")
            lines.append(thin)
            for w in self.warnings:
                lines.append(f"  ! {w}")

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
# Helpers
# ══════════════════════════════════════════════════════════════════════════

def _parse_rrsig_times(rrsig_rdata) -> tuple:
    """Extract inception and expiration as datetime objects."""
    try:
        # dnspython stores these as integers (seconds since epoch)
        inception = datetime.datetime.utcfromtimestamp(rrsig_rdata.inception)
        expiration = datetime.datetime.utcfromtimestamp(rrsig_rdata.expiration)
        return inception, expiration
    except Exception:
        return None, None


# ══════════════════════════════════════════════════════════════════════════
# Core analysis
# ══════════════════════════════════════════════════════════════════════════

def analyze_key_lifecycle(domain: str) -> KeyLifecycleReport:
    """
    Retrieve DNSKEY, RRSIG, and DS records for *domain* and analyze
    the key lifecycle – detecting rollovers, mismatches, and anomalies.
    """
    domain = domain.rstrip(".")
    report = KeyLifecycleReport(domain=domain)

    # ── Step 1: Fetch DNSKEY ──────────────────────────────────────────────
    try:
        msg_dnskey = _query_with_do(domain, dns.rdatatype.DNSKEY)
        dnskey_rrset = _extract_rrset(msg_dnskey, domain, dns.rdatatype.DNSKEY)
        dnskey_rrsig_rrset = _extract_rrset(msg_dnskey, domain, dns.rdatatype.RRSIG)
    except Exception as exc:
        report.errors.append(f"Failed to fetch DNSKEY: {exc}")
        report.status = "NOT_SIGNED"
        return report

    if dnskey_rrset is None:
        report.status = "NOT_SIGNED"
        report.observations.append("No DNSKEY records found – domain is not DNSSEC-signed")
        return report

    # ── Step 2: Fetch DS from parent ──────────────────────────────────────
    ds_records = []
    try:
        msg_ds = _query_with_do(domain, dns.rdatatype.DS)
        ds_rrset = _extract_rrset(msg_ds, domain, dns.rdatatype.DS)
        if ds_rrset:
            ds_records = list(ds_rrset)
    except Exception as exc:
        report.warnings.append(f"DS fetch failed: {exc}")

    report.num_ds = len(ds_records)
    report.ds_key_tags = [ds.key_tag for ds in ds_records]

    # ── Step 3: Parse each DNSKEY ─────────────────────────────────────────
    # Collect RRSIG key_tags that sign DNSKEY
    dnskey_signer_tags: Set[int] = set()
    dnskey_rrsigs_list = []
    if dnskey_rrsig_rrset:
        for sig in dnskey_rrsig_rrset:
            if hasattr(sig, 'type_covered') and sig.type_covered == dns.rdatatype.DNSKEY:
                dnskey_signer_tags.add(sig.key_tag)
                dnskey_rrsigs_list.append(sig)

    # Also fetch a common RRtype (A) to see which ZSK signs zone data
    zone_signer_tags: Set[int] = set()
    zone_rrsig_times: Dict[int, tuple] = {}
    try:
        msg_a = _query_with_do(domain, dns.rdatatype.A)
        a_rrsig = _extract_rrset(msg_a, domain, dns.rdatatype.RRSIG)
        if a_rrsig:
            for sig in a_rrsig:
                if hasattr(sig, 'type_covered') and sig.type_covered == dns.rdatatype.A:
                    zone_signer_tags.add(sig.key_tag)
                    inc, exp = _parse_rrsig_times(sig)
                    zone_rrsig_times[sig.key_tag] = (inc, exp)
    except Exception:
        pass

    ksks: List[KeyInfo] = []
    zsks: List[KeyInfo] = []

    for dnskey in dnskey_rrset:
        tag = dns.dnssec.key_id(dnskey)
        is_sep = bool(dnskey.flags & 0x0001)   # SEP flag = KSK
        key_type = "KSK" if is_sep else "ZSK"

        ki = KeyInfo(
            key_tag=tag,
            flags=dnskey.flags,
            algorithm=dnskey.algorithm,
            protocol=dnskey.protocol,
            key_type=key_type,
        )

        # Estimate key size from the public key material
        if hasattr(dnskey, 'key'):
            ki.key_length_bits = len(dnskey.key) * 8

        # Check DS match
        for ds in ds_records:
            if ds.key_tag == tag and ds.algorithm == dnskey.algorithm:
                # Verify digest matches
                try:
                    computed = _compute_ds_digest(
                        dnskey, dns.name.from_text(domain), ds.digest_type)
                    if computed == ds.digest:
                        ki.has_matching_ds = True
                except Exception:
                    pass

        # Check signing roles
        ki.is_signing_dnskey = tag in dnskey_signer_tags
        ki.is_signing_zone = tag in zone_signer_tags

        # Attach RRSIG timing
        if tag in zone_rrsig_times:
            ki.rrsig_inception, ki.rrsig_expiration = zone_rrsig_times[tag]
        elif dnskey_rrsigs_list:
            for sig in dnskey_rrsigs_list:
                if sig.key_tag == tag:
                    ki.rrsig_inception, ki.rrsig_expiration = _parse_rrsig_times(sig)
                    break

        if is_sep:
            ksks.append(ki)
        else:
            zsks.append(ki)

        report.keys.append(ki)

    report.num_ksks = len(ksks)
    report.num_zsks = len(zsks)

    # ── Step 4: Detect lifecycle state ────────────────────────────────────

    # Basic observations
    report.observations.append(
        f"Found {len(ksks)} KSK(s) and {len(zsks)} ZSK(s)")

    # Check for algorithm diversity
    algos = set(k.algorithm for k in report.keys)
    if len(algos) > 1:
        report.observations.append(
            f"Multiple algorithms in use: {sorted(algos)} "
            f"(may indicate algorithm rollover)")

    # ── KSK rollover detection ────────────────────────────────────────────
    ksk_rollover = False
    if len(ksks) > 1:
        report.observations.append(
            f"Multiple KSKs present: key_tags = {[k.key_tag for k in ksks]}")
        ds_matched = [k for k in ksks if k.has_matching_ds]
        ds_unmatched = [k for k in ksks if not k.has_matching_ds]

        if ds_matched and ds_unmatched:
            ksk_rollover = True
            report.observations.append(
                f"KSK rollover in progress: "
                f"DS matches key_tag(s) {[k.key_tag for k in ds_matched]}, "
                f"no DS for key_tag(s) {[k.key_tag for k in ds_unmatched]}")
            report.observations.append(
                "Old + new KSK present – DS matches old KSK only "
                "(pre-publish or double-DS phase)")
        elif len(ds_matched) > 1:
            ksk_rollover = True
            report.observations.append(
                f"Double-DS rollover: multiple KSKs with matching DS records "
                f"(key_tags {[k.key_tag for k in ds_matched]})")
        elif not ds_matched:
            report.warnings.append(
                "Multiple KSKs but NO DS matches any of them – broken chain!")

    # ── ZSK rollover detection ────────────────────────────────────────────
    zsk_rollover = False
    if len(zsks) > 1:
        report.observations.append(
            f"Multiple ZSKs present: key_tags = {[k.key_tag for k in zsks]}")
        signing_zsks = [z for z in zsks if z.is_signing_zone]
        non_signing_zsks = [z for z in zsks if not z.is_signing_zone]

        if signing_zsks and non_signing_zsks:
            zsk_rollover = True
            report.observations.append(
                f"ZSK rollover in progress: "
                f"active signer = {[z.key_tag for z in signing_zsks]}, "
                f"pre-published / retiring = {[z.key_tag for z in non_signing_zsks]}")

    # ── DS mismatch detection ─────────────────────────────────────────────
    ds_tag_set = set(report.ds_key_tags)
    ksk_tag_set = set(k.key_tag for k in ksks)

    orphan_ds = ds_tag_set - ksk_tag_set
    if orphan_ds:
        report.warnings.append(
            f"DS record(s) reference key_tag(s) {sorted(orphan_ds)} "
            f"not found in published DNSKEY set – stale DS or timing issue")

    ksk_without_ds = ksk_tag_set - ds_tag_set
    if ksk_without_ds and len(ksks) == 1:
        report.warnings.append(
            f"Single KSK (key_tag={list(ksk_without_ds)[0]}) has no matching DS – "
            f"chain of trust is broken")

    # ── Determine overall status ──────────────────────────────────────────
    if ksk_rollover and zsk_rollover:
        report.status = "DOUBLE_ROLLOVER"
    elif ksk_rollover:
        report.status = "KSK_ROLLOVER"
    elif zsk_rollover:
        report.status = "ZSK_ROLLOVER"
    elif orphan_ds:
        report.status = "DS_MISMATCH"
    elif report.warnings:
        report.status = "ANOMALY"
    else:
        report.status = "STABLE"

    # ── RRSIG timing observations ─────────────────────────────────────────
    now = datetime.datetime.utcnow()
    for k in report.keys:
        if k.rrsig_expiration:
            days_left = (k.rrsig_expiration - now).days
            if days_left < 0:
                report.warnings.append(
                    f"RRSIG for key_tag={k.key_tag} EXPIRED "
                    f"{abs(days_left)} day(s) ago!")
            elif days_left < 7:
                report.warnings.append(
                    f"RRSIG for key_tag={k.key_tag} expires in "
                    f"{days_left} day(s) – renewal imminent")

    return report


# ══════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <domain> [domain2] ...")
        print()
        print("Examples:")
        print(f"  {sys.argv[0]} cloudflare.com")
        print(f"  {sys.argv[0]} google.com  example.com  dnssec-failed.org")
        sys.exit(1)

    for domain_arg in sys.argv[1:]:
        report = analyze_key_lifecycle(domain_arg)
        print(report)
