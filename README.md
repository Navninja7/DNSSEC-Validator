# DNSSEC-Validator

This project is a part of the CS6903 Network Security course taken in the Jan-May 2026 Semester at IIT Hyderabad. THe project implements a DNSSEC validation system including:

## DNSSEC validation module (Q1)
## Recursive DNSSEC resolver (Q2)
## NSEC/NSEC3 handling (Q3)
## Key lifecycle analysis (Q4)
## Tampering detection demo (Q5)


# Prerequisites
Python 3.8+
Internet connection (required for DNS queries)

# Install required dependency:

pip install -r requirements.txt

# Project Files
dnssec_validator.py → DNSSEC validation module (Q1)
dnssec_resolver.py → Recursive DNSSEC resolver (Q2)
dnssec_nsec_resolver.py → Resolver with NSEC/NSEC3 (Q3)
dnssec_key_lifecycle.py → Key lifecycle analysis (Q4)
dnssec_tamper_demo.py → Tampering detection demo (Q5)

# How to Run
1. DNSSEC Validation (Q1)
python dnssec_validator.py <domain name> <record type>
2. Recursive Resolver (Q2)
python dnssec_resolver.py  <domain name> <record type>
3. NSEC/NSEC3 Resolver (Q3)
python dnssec_nsec_resolver.py <domain name> <record type>
4. Key Lifecycle Analysis (Q4) 
python dnssec_key_lifecycle.py <domain name> <record type>
5. Tampering Detection Demo (Q5) 
python dnssec_tamper_demo.py <domain name> <record type>

# Notes
Ensure firewall/network allows DNS queries (UDP/TCP port 53).
If timeouts occur, retry or check internet connectivity.
Outputs will display DNSSEC validation steps and results.
System Description
OS: Linux / Windows / macOS
Language: Python
Library Used: dnspython
