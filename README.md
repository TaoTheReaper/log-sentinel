# log-sentinel

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)
![No Dependencies](https://img.shields.io/badge/Dependencies-stdlib%20only-green?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange?style=for-the-badge)

## Overview

Windows Event Log analyzer that detects suspicious activity patterns — brute force, lateral movement, privilege escalation, persistence, and defense evasion — without needing a full SIEM.

## Why this project

Log analysis is the core daily skill of a SOC analyst. This tool demonstrates detection rule logic, MITRE ATT&CK mapping, and the ability to identify attacker behavior from raw event data — using only Python stdlib.

## Detection Rules

| Rule ID | Name | MITRE | Severity |
|---------|------|-------|----------|
| BRUTE-001 | Brute Force — Failed Logons | T1110 | HIGH |
| PRIV-001 | Privilege Escalation — Special Logon | T1078 | MEDIUM |
| LAT-001 | Lateral Movement — NTLM Network Logon | T1550.002 | MEDIUM |
| CRED-001 | Credential Dump — LSASS Access | T1003.001 | CRITICAL |
| RECON-001 | Recon — Account Enumeration | T1087.002 | MEDIUM |
| PERSIST-001 | Persistence — Scheduled Task Created | T1053.005 | MEDIUM |
| PERSIST-002 | Persistence — New Service Installed | T1543.003 | HIGH |
| AUDIT-001 | Defense Evasion — Audit Log Cleared | T1070.001 | CRITICAL |
| ACC-001 | Account Management — New User Created | T1136.001 | LOW |
| ACC-002 | Account Management — User Added to Admin Group | T1098 | HIGH |

## Setup

```bash
git clone https://github.com/TaoTheReaper/log-sentinel
cd log-sentinel
# No dependencies — stdlib only
```

## Usage

```bash
# Analyze a log file
python3 log-sentinel.py events.txt

# Save JSON report
python3 log-sentinel.py events.txt -o alerts.json

# Debug mode
python3 log-sentinel.py events.txt -v
```

## Input Format

Accepts any text file containing Windows Event IDs with optional key=value fields. Supports:
- Windows Security Log CSV exports
- Generic text logs with EventID mentions
- Custom formats with key=value pairs

## Lessons Learned

- EventID 1102 (log cleared) is a critical indicator — legitimate admins rarely clear logs
- EventID 4672 alone is noisy; correlate with 4624 logon type for better signal
- Brute force threshold must be tuned per environment — 10 failures may be normal in some orgs
