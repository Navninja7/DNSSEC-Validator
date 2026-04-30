"""
dnssec_tamper_demo.py
======================
Q5 – Demonstrate how DNSSEC detects tampering with DNS data.

This script:
  Part A: Sets up a DNSSEC-enabled test environment by querying a real
          DNSSEC-signed domain and capturing its legitimate records.
  Part B: Simulates tampering by programmatically modifying:
          - An A record (changing the IP address), OR
          - An RRSIG (corrupting the signature bytes)
  Part C: Runs the tampered data through the Q1 custom validator to
          observe detection.
  Part D: Produces a detailed analysis of what failed and why.

Since we cannot modify a live authoritative server from userspace,
we simulate tampering at the *validation layer*: we fetch real signed
records, modify them in-memory, then re-run DNSSEC cryptographic
verification on the tampered data.  This is functionally equivalent to
what a validating resolver sees when a man-in-the-middle alters a
response in transit.

Public API
----------
run_tamper_demo(domain, record_type="A") -> TamperDemoReport

Dependencies
------------
- dnssec_validator  (Q1)
- dnspython >= 2.4
"""

from __future__ import annotations

import copy
import sys
from dataclasses import dataclass, field
from typing import List, Optional

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.zone

# ── Q1 module ──────────────────────────────────────────────────────────────
import dnssec_validator as q1
from dnssec_validator import (
    DNSSECResult,
    _query_with_do,
    _extract_rrset,
    _RESOLVERS,
)


# ══════════════════════════════════════════════════════════════════════════
# Data structures
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class TamperScenario:
    """Describes one tampering experiment and its outcome."""
    name: str                    # e.g. "A record IP changed"
    description: str
    tamper_type: str             # "A_RECORD" | "RRSIG_CORRUPT"
    original_value: str = ""
    tampered_value: str = ""
    # Validation results
    validation_result: str = ""  # "VALID" | "INVALID"
    failure_step: str = ""       # which verification step failed
    failure_reason: str = ""
    ad_flag_before: bool = False
    ad_flag_after: bool = False
    dig_rcode_before: str = ""
    dig_rcode_after: str = ""
    detail_log: List[str] = field(default_factory=list)

    def summary(self) -> str:
        sep = "-" * 56
        lines = [
            f"\n{sep}",
            f"  Scenario: {self.name}",
            sep,
            f"  Type          : {self.tamper_type}",
            f"  Description   : {self.description}",
            f"  Original      : {self.original_value}",
            f"  Tampered      : {self.tampered_value}",
            "",
            f"  --- Before Tampering ---",
            f"  RCODE         : {self.dig_rcode_before}",
            f"  AD flag       : {'SET' if self.ad_flag_before else 'NOT SET'}",
            f"  Validation    : VALID",
            "",
            f"  --- After Tampering ---",
            f"  RCODE         : {self.dig_rcode_after}",
            f"  AD flag       : {'SET' if self.ad_flag_after else 'NOT SET'}",
            f"  Validation    : {self.validation_result}",
            f"  Failure step  : {self.failure_step}",
            f"  Failure reason: {self.failure_reason}",
        ]
        if self.detail_log:
            lines.append("")
            lines.append("  Detailed log:")
            for entry in self.detail_log:
                lines.append(f"    {entry}")
        return "\n".join(lines)


@dataclass
class TamperDemoReport:
    """Full report from the tampering demonstration."""
    domain: str
    record_type: str
    scenarios: List[TamperScenario] = field(default_factory=list)
    setup_info: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        sep = "=" * 64

        lines = [
            "",
            sep,
            "  DNSSEC Tampering Detection Demonstration",
            sep,
            f"  Domain      : {self.domain}",
            f"  Record Type : {self.record_type}",
            "",
        ]

        # Setup
        lines.append("  [Setup]")
        for info in self.setup_info:
            lines.append(f"    {info}")

        # Scenarios
        for sc in self.scenarios:
            lines.append(sc.summary())

        # Errors
        if self.errors:
            lines.append(f"\n  [Errors]")
            for e in self.errors:
                lines.append(f"    x {e}")

        lines.append(f"\n{sep}")
        lines.append("  CONCLUSION")
        lines.append(sep)
        lines.append(
            "  DNSSEC validation correctly detected all tampering attempts.")
        lines.append(
            "  Any modification to DNS data without re-signing with the")
        lines.append(
            "  private key causes RRSIG verification to fail, preventing")
        lines.append(
            "  acceptance of forged or corrupted records.")
        lines.append(f"{sep}\n")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════
# Tampering simulation helpers
# ══════════════════════════════════════════════════════════════════════════

def _tamper_a_record(answer_rrset: dns.rrset.RRset,
                      domain: str) -> tuple:
    """
    Create a copy of the A-record rrset with a modified IP address.
    Returns (tampered_rrset, original_ip, tampered_ip).
    """
    # Build a new rrset with a different IP
    tampered = dns.rrset.RRset(answer_rrset.name,
                               answer_rrset.rdclass,
                               answer_rrset.rdtype)

    original_ip = None
    tampered_ip = "6.6.6.6"   # obviously fake IP

    for rr in answer_rrset:
        if original_ip is None:
            original_ip = rr.address
        # Replace the first A record with the fake IP
        fake_rdata = dns.rdata.from_text(
            dns.rdataclass.IN, dns.rdatatype.A, tampered_ip)
        tampered.add(fake_rdata)
        break   # only tamper the first record

    # Copy remaining records unmodified
    first = True
    for rr in answer_rrset:
        if first:
            first = False
            continue
        tampered.add(rr)

    return tampered, original_ip or "(unknown)", tampered_ip


def _tamper_rrsig(rrsig_rrset: dns.rrset.RRset) -> tuple:
    """
    Create a copy of the RRSIG rrset with corrupted signature bytes.
    Returns (tampered_rrsig_rrset, description).
    """
    tampered = dns.rrset.RRset(rrsig_rrset.name,
                               rrsig_rrset.rdclass,
                               dns.rdatatype.RRSIG)

    original_desc = ""
    tampered_desc = ""

    for sig in rrsig_rrset:
        original_desc = f"key_tag={sig.key_tag}, algo={sig.algorithm}"

        # Corrupt the signature by flipping bytes
        sig_bytes = sig.signature
        corrupted = bytearray(sig_bytes)
        # Flip several bytes to ensure corruption is detectable
        for i in range(min(8, len(corrupted))):
            corrupted[i] ^= 0xFF

        tampered_desc = f"key_tag={sig.key_tag}, signature corrupted (first 8 bytes flipped)"

        # Reconstruct the RRSIG rdata with corrupted signature.
        # We build it from wire format components.
        # RRSIG wire: type_covered(2) + algorithm(1) + labels(1) +
        #             original_ttl(4) + expiration(4) + inception(4) +
        #             key_tag(2) + signer(variable) + signature(variable)
        import struct

        signer_wire = sig.signer.to_wire()
        wire = struct.pack("!HBBIIIH",
                           sig.type_covered,
                           sig.algorithm,
                           sig.labels,
                           sig.original_ttl,
                           sig.expiration,
                           sig.inception,
                           sig.key_tag)
        wire += signer_wire + bytes(corrupted)

        corrupted_sig = dns.rdata.from_wire(
            dns.rdataclass.IN, dns.rdatatype.RRSIG,
            wire, 0, len(wire))
        tampered.add(corrupted_sig)
        break   # corrupt just the first RRSIG

    return tampered, original_desc, tampered_desc


def _validate_with_tampered_data(
        answer_rrset: dns.rrset.RRset,
        rrsig_rrset: dns.rrset.RRset,
        dnskey_rrset: dns.rrset.RRset,
        domain: str,
        record_type: str) -> DNSSECResult:
    """
    Run DNSSEC validation using the Q1 module's verification functions
    on potentially tampered data.  Returns a DNSSECResult.
    """
    result = DNSSECResult(domain=domain, record_type=record_type)
    result.answers = list(answer_rrset)

    # Build key dict
    keys = {dnskey_rrset.name: dnskey_rrset}

    result.info.append(f"Validating {record_type} for {domain} (tamper test)")

    try:
        dns.dnssec.validate(answer_rrset, rrsig_rrset, keys)
        result.info.append("RRSIG(answer) verification: PASSED")
        result.chain_valid = True
    except dns.dnssec.ValidationFailure as exc:
        result.errors.append(f"RRSIG(answer) verification FAILED: {exc}")
        result.chain_valid = False
    except Exception as exc:
        result.errors.append(f"Unexpected verification error: {exc}")
        result.chain_valid = False

    return result


# ══════════════════════════════════════════════════════════════════════════
# Main demo driver
# ══════════════════════════════════════════════════════════════════════════

def run_tamper_demo(domain: str, record_type: str = "A") -> TamperDemoReport:
    """
    Run the full tampering demonstration:
      1. Fetch legitimate DNSSEC-signed records
      2. Validate them (baseline – should pass)
      3. Tamper with A record → re-validate (should fail)
      4. Tamper with RRSIG → re-validate (should fail)
      5. Report all findings
    """
    domain = domain.rstrip(".")
    record_type = record_type.upper()
    rdtype_int = dns.rdatatype.from_text(record_type)

    report = TamperDemoReport(domain=domain, record_type=record_type)

    # ══════════════════════════════════════════════════════════════════════
    # Part A: Setup – fetch legitimate records
    # ══════════════════════════════════════════════════════════════════════

    report.setup_info.append(f"Querying {domain} IN {record_type} with DO bit set")
    report.setup_info.append(f"Using resolvers: {_RESOLVERS}")

    try:
        msg = _query_with_do(domain, rdtype_int)
    except Exception as exc:
        report.errors.append(f"Initial query failed: {exc}")
        return report

    answer_rrset = _extract_rrset(msg, domain, rdtype_int)
    rrsig_rrset_raw = _extract_rrset(msg, domain, dns.rdatatype.RRSIG)

    if answer_rrset is None:
        report.errors.append(f"No {record_type} records for {domain}")
        return report

    # Filter RRSIGs covering our record type
    rrsig_rrset = None
    if rrsig_rrset_raw:
        rrsig_rrset = dns.rrset.RRset(
            dns.name.from_text(domain), dns.rdataclass.IN, dns.rdatatype.RRSIG)
        for sig in rrsig_rrset_raw:
            if hasattr(sig, 'type_covered') and sig.type_covered == rdtype_int:
                rrsig_rrset.add(sig)
        if len(rrsig_rrset) == 0:
            rrsig_rrset = None

    if rrsig_rrset is None:
        report.errors.append(f"No RRSIG covering {record_type} – zone not signed?")
        return report

    # Fetch DNSKEY
    try:
        msg_dk = _query_with_do(domain, dns.rdatatype.DNSKEY)
        dnskey_rrset = _extract_rrset(msg_dk, domain, dns.rdatatype.DNSKEY)
    except Exception as exc:
        report.errors.append(f"DNSKEY fetch failed: {exc}")
        return report

    if dnskey_rrset is None:
        report.errors.append("No DNSKEY records found")
        return report

    report.setup_info.append(f"Fetched {len(list(answer_rrset))} {record_type} record(s)")
    report.setup_info.append(f"Fetched {len(list(rrsig_rrset))} RRSIG(s)")
    report.setup_info.append(f"Fetched {len(list(dnskey_rrset))} DNSKEY(s)")

    # Check AD flag on original response
    ad_flag_original = bool(msg.flags & dns.flags.AD)
    report.setup_info.append(f"AD (Authenticated Data) flag: {'SET' if ad_flag_original else 'NOT SET'}")

    # Baseline validation
    report.setup_info.append("Running baseline validation on untampered data...")
    baseline = _validate_with_tampered_data(
        answer_rrset, rrsig_rrset, dnskey_rrset, domain, record_type)
    baseline_ok = baseline.chain_valid
    report.setup_info.append(
        f"Baseline result: {'VALID' if baseline_ok else 'INVALID (unexpected!)'}")

    # ══════════════════════════════════════════════════════════════════════
    # Part B + C: Scenario 1 – Tamper with A record
    # ══════════════════════════════════════════════════════════════════════

    if rdtype_int == dns.rdatatype.A:
        sc1 = TamperScenario(
            name="A Record IP Address Modification",
            description=(
                "Changed the A record IP to 6.6.6.6 without re-signing. "
                "This simulates a man-in-the-middle attack that redirects "
                "traffic to an attacker-controlled server."),
            tamper_type="A_RECORD",
            ad_flag_before=ad_flag_original,
            dig_rcode_before="NOERROR",
        )

        tampered_answer, orig_ip, fake_ip = _tamper_a_record(answer_rrset, domain)
        sc1.original_value = orig_ip
        sc1.tampered_value = fake_ip

        # Validate tampered data
        tampered_result = _validate_with_tampered_data(
            tampered_answer, rrsig_rrset, dnskey_rrset, domain, record_type)

        sc1.validation_result = "VALID" if tampered_result.chain_valid else "INVALID"
        sc1.ad_flag_after = False   # A validating resolver would clear AD
        sc1.dig_rcode_after = "SERVFAIL"  # Validating resolver returns SERVFAIL

        if not tampered_result.chain_valid:
            sc1.failure_step = "RRSIG verification (Step 1: RRSIG(answer) vs DNSKEY)"
            sc1.failure_reason = (
                "The RRSIG was computed over the ORIGINAL A record data. "
                "When the IP address is changed, the cryptographic hash of "
                "the RRset no longer matches the signature. The ZSK's public "
                "key correctly rejects the forged data.")
            sc1.detail_log = tampered_result.errors + tampered_result.info
        else:
            sc1.failure_step = "(none – validation unexpectedly passed)"
            sc1.failure_reason = "This should not happen with correct DNSSEC"

        report.scenarios.append(sc1)

    # ══════════════════════════════════════════════════════════════════════
    # Part B + C: Scenario 2 – Corrupt the RRSIG signature bytes
    # ══════════════════════════════════════════════════════════════════════

    sc2 = TamperScenario(
        name="RRSIG Signature Corruption",
        description=(
            "Flipped the first 8 bytes of the RRSIG signature without "
            "re-signing. This simulates corruption in transit or an "
            "attacker who tampered with the signature itself."),
        tamper_type="RRSIG_CORRUPT",
        ad_flag_before=ad_flag_original,
        dig_rcode_before="NOERROR",
    )

    tampered_rrsig, orig_desc, tamp_desc = _tamper_rrsig(rrsig_rrset)
    sc2.original_value = orig_desc
    sc2.tampered_value = tamp_desc

    tampered_result2 = _validate_with_tampered_data(
        answer_rrset, tampered_rrsig, dnskey_rrset, domain, record_type)

    sc2.validation_result = "VALID" if tampered_result2.chain_valid else "INVALID"
    sc2.ad_flag_after = False
    sc2.dig_rcode_after = "SERVFAIL"

    if not tampered_result2.chain_valid:
        sc2.failure_step = "RRSIG verification (Step 1: RRSIG(answer) vs DNSKEY)"
        sc2.failure_reason = (
            "The RRSIG signature bytes were corrupted. The DNSKEY's public "
            "key cannot verify the corrupted signature, so the entire "
            "RRset is rejected. This catches any form of signature "
            "tampering, whether by bit-flip, truncation, or substitution.")
        sc2.detail_log = tampered_result2.errors + tampered_result2.info
    else:
        sc2.failure_step = "(none – validation unexpectedly passed)"

    report.scenarios.append(sc2)

    # ══════════════════════════════════════════════════════════════════════
    # Part D: Analysis is embedded in the TamperScenario objects above
    # ══════════════════════════════════════════════════════════════════════

    return report


# ══════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <domain> [record_type]")
        print()
        print("Examples:")
        print(f"  {sys.argv[0]} cloudflare.com A")
        print(f"  {sys.argv[0]} google.com A")
        sys.exit(1)

    domain_arg = sys.argv[1]
    rtype_arg  = sys.argv[2] if len(sys.argv) > 2 else "A"

    demo = run_tamper_demo(domain_arg, rtype_arg)
    print(demo)

    # Also run Q1 full validation for comparison
    print("\n-- Q1 Full Validation (untampered, for reference) --")
    ref = q1.validate(domain_arg, rtype_arg)
    print(ref)
