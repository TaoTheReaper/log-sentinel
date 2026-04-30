#!/usr/bin/env python3
"""log-sentinel — Windows Event Log analyzer for suspicious activity patterns."""

import argparse
import json
import logging
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("log-sentinel")

C = {
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "cyan": "\033[96m", "magenta": "\033[95m", "bold": "\033[1m", "reset": "\033[0m"
}

SEV_COLOR = {
    "CRITICAL": "\033[91m", "HIGH": "\033[91m",
    "MEDIUM": "\033[93m",   "LOW": "\033[92m", "INFO": "\033[96m"
}

# Detection rules
RULES = [
    {
        "id": "BRUTE-001",
        "name": "Brute Force — Failed Logons",
        "severity": "HIGH",
        "description": "More than 10 failed logons (EventID 4625) from the same source in the log.",
        "event_ids": [4625],
        "threshold": 10,
        "group_by": "ip",
        "mitre": "T1110",
    },
    {
        "id": "PRIV-001",
        "name": "Privilege Escalation — Special Logon",
        "severity": "MEDIUM",
        "description": "Special privileges assigned to new logon (EventID 4672) — admin-equivalent rights.",
        "event_ids": [4672],
        "threshold": 1,
        "group_by": None,
        "mitre": "T1078",
    },
    {
        "id": "LAT-001",
        "name": "Lateral Movement — Network Logon (NTLM)",
        "severity": "MEDIUM",
        "description": "Network logon (Type 3) using NTLM from unexpected source.",
        "event_ids": [4624],
        "threshold": 1,
        "group_by": "ip",
        "mitre": "T1550.002",
        "filter": {"logon_type": "3", "auth_package": "NTLM"},
    },
    {
        "id": "CRED-001",
        "name": "Credential Dump — LSASS Access",
        "severity": "CRITICAL",
        "description": "Process accessed LSASS memory (EventID 4656/4663) — potential credential dumping.",
        "event_ids": [4656, 4663],
        "threshold": 1,
        "group_by": None,
        "mitre": "T1003.001",
        "filter": {"object_name": "lsass"},
    },
    {
        "id": "RECON-001",
        "name": "Recon — Account Enumeration",
        "severity": "MEDIUM",
        "description": "More than 20 account lookups (EventID 4661) — possible AD enumeration.",
        "event_ids": [4661],
        "threshold": 20,
        "group_by": "user",
        "mitre": "T1087.002",
    },
    {
        "id": "PERSIST-001",
        "name": "Persistence — Scheduled Task Created",
        "severity": "MEDIUM",
        "description": "A scheduled task was created (EventID 4698).",
        "event_ids": [4698],
        "threshold": 1,
        "group_by": None,
        "mitre": "T1053.005",
    },
    {
        "id": "PERSIST-002",
        "name": "Persistence — New Service Installed",
        "severity": "HIGH",
        "description": "A new service was installed (EventID 7045) — possible PsExec or malware persistence.",
        "event_ids": [7045],
        "threshold": 1,
        "group_by": None,
        "mitre": "T1543.003",
    },
    {
        "id": "AUDIT-001",
        "name": "Defense Evasion — Audit Log Cleared",
        "severity": "CRITICAL",
        "description": "Security event log was cleared (EventID 1102/104).",
        "event_ids": [1102, 104],
        "threshold": 1,
        "group_by": None,
        "mitre": "T1070.001",
    },
    {
        "id": "ACC-001",
        "name": "Account Management — New User Created",
        "severity": "LOW",
        "description": "A new user account was created (EventID 4720).",
        "event_ids": [4720],
        "threshold": 1,
        "group_by": None,
        "mitre": "T1136.001",
    },
    {
        "id": "ACC-002",
        "name": "Account Management — User Added to Admin Group",
        "severity": "HIGH",
        "description": "A user was added to a privileged group (EventID 4728/4732/4756).",
        "event_ids": [4728, 4732, 4756],
        "threshold": 1,
        "group_by": None,
        "mitre": "T1098",
    },
]

# ---------- log parsers ----------
def parse_line(line: str) -> dict | None:
    """
    Parses a single log line. Supports common formats:
    - Windows Security Log CSV export
    - Generic key=value format
    - Plain EventID mention
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    entry: dict = {"raw": line}

    # Try to extract EventID
    eid_match = re.search(r"EventID[=:\s]+(\d+)", line, re.I)
    if not eid_match:
        eid_match = re.search(r"\b(4624|4625|4648|4656|4661|4662|4663|4672|4698|4720|4728|4732|4756|7045|1102|104)\b", line)
    if eid_match:
        entry["event_id"] = int(eid_match.group(1))

    # Extract IP
    ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
    if ip_match:
        entry["ip"] = ip_match.group(1)

    # Extract username
    user_match = re.search(r"(?:AccountName|SubjectUserName|TargetUserName)[=:\s]+([^\s,;]+)", line, re.I)
    if user_match:
        entry["user"] = user_match.group(1)

    # Extract logon type
    lt_match = re.search(r"LogonType[=:\s]+(\d+)", line, re.I)
    if lt_match:
        entry["logon_type"] = lt_match.group(1)

    # Extract auth package
    auth_match = re.search(r"AuthenticationPackageName[=:\s]+([^\s,;]+)", line, re.I)
    if auth_match:
        entry["auth_package"] = auth_match.group(1)

    # Extract object name (for LSASS detection)
    obj_match = re.search(r"ObjectName[=:\s]+([^\s,;]+)", line, re.I)
    if obj_match:
        entry["object_name"] = obj_match.group(1).lower()

    return entry if "event_id" in entry else None

def parse_log_file(path: Path) -> list[dict]:
    entries = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as e:
        print(f"{C['red']}[!] Cannot read file: {e}{C['reset']}")
        sys.exit(1)

    for line in text.splitlines():
        entry = parse_line(line)
        if entry:
            entries.append(entry)

    log.debug("Parsed %d entries from %s", len(entries), path)
    return entries

# ---------- detection engine ----------
def run_detections(entries: list[dict]) -> list[dict]:
    alerts = []

    for rule in RULES:
        matching = []
        for e in entries:
            if e.get("event_id") not in rule["event_ids"]:
                continue

            # Apply filters
            filters = rule.get("filter", {})
            match = True
            for k, v in filters.items():
                entry_val = str(e.get(k, "")).lower()
                if v.lower() not in entry_val:
                    match = False
                    break
            if not match:
                continue
            matching.append(e)

        if not matching:
            continue

        group_by = rule.get("group_by")
        if group_by:
            groups: dict = defaultdict(list)
            for e in matching:
                key = e.get(group_by, "unknown")
                groups[key].append(e)

            for key, items in groups.items():
                if len(items) >= rule["threshold"]:
                    alerts.append({
                        "rule_id":     rule["id"],
                        "name":        rule["name"],
                        "severity":    rule["severity"],
                        "description": rule["description"],
                        "mitre":       rule.get("mitre"),
                        "count":       len(items),
                        "key":         f"{group_by}={key}",
                        "sample":      items[:3],
                    })
        else:
            if len(matching) >= rule["threshold"]:
                alerts.append({
                    "rule_id":     rule["id"],
                    "name":        rule["name"],
                    "severity":    rule["severity"],
                    "description": rule["description"],
                    "mitre":       rule.get("mitre"),
                    "count":       len(matching),
                    "key":         None,
                    "sample":      matching[:3],
                })

    # sort by severity
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    alerts.sort(key=lambda x: order.get(x["severity"], 5))
    return alerts

# ---------- output ----------
def print_alerts(alerts: list[dict], total_entries: int):
    print(f"{C['cyan']}\n{'='*60}")
    print(f"  LOG SENTINEL — {total_entries} events analyzed")
    print(f"{'='*60}{C['reset']}")

    if not alerts:
        print(f"\n{C['green']}  No suspicious activity detected.{C['reset']}")
    else:
        print(f"\n{C['bold']}  {len(alerts)} alert(s) triggered:{C['reset']}\n")
        for a in alerts:
            sc = SEV_COLOR.get(a["severity"], C["reset"])
            print(f"  {sc}[{a['severity']}]{C['reset']} {C['bold']}{a['name']}{C['reset']}  "
                  f"[{a['rule_id']}] MITRE: {a['mitre']}")
            print(f"    {a['description']}")
            print(f"    Count: {a['count']}"
                  + (f"  ({a['key']})" if a['key'] else ""))
            print()

    counts = defaultdict(int)
    for a in alerts:
        counts[a["severity"]] += 1
    print(f"{C['cyan']}Summary:{C['reset']} "
          f"{C['red']}CRITICAL:{counts['CRITICAL']} HIGH:{counts['HIGH']}{C['reset']}  "
          f"{C['yellow']}MEDIUM:{counts['MEDIUM']}{C['reset']}  "
          f"{C['green']}LOW:{counts['LOW']}{C['reset']}")
    print(f"{C['cyan']}{'='*60}{C['reset']}")

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log-sentinel",
        description="Analyze Windows event logs for suspicious patterns (brute force, lateral movement, persistence...).",
        epilog=(
            "Examples:\n"
            "  python log-sentinel.py events.txt\n"
            "  python log-sentinel.py events.txt -o alerts.json -v\n\n"
            "Input format: any text file containing EventID numbers with optional key=value fields.\n"
            "Supports Windows Security Log exports (.csv, .txt, .log)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("logfile",         help="Path to log file (txt/csv/log)")
    p.add_argument("-o", "--output",  metavar="FILE", help="Save JSON report")
    p.add_argument("-v", "--verbose", action="store_true")
    return p

def main():
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    path = Path(args.logfile)
    if not path.exists():
        print(f"{C['red']}[!] File not found: {path}{C['reset']}")
        sys.exit(1)

    print(f"{C['cyan']}[*] Parsing {path}...{C['reset']}")
    entries = parse_log_file(path)
    print(f"{C['cyan']}[*] Running {len(RULES)} detection rules...{C['reset']}")
    alerts  = run_detections(entries)

    print_alerts(alerts, len(entries))

    if args.output:
        report = {
            "file":      str(path),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_events": len(entries),
            "alerts":    alerts,
        }
        tmp = args.output + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        os.replace(tmp, args.output)
        print(f"{C['green']}[+] Report saved: {args.output}{C['reset']}")

if __name__ == "__main__":
    main()
