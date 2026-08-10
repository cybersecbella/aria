"""Local MITRE ATT&CK technique reference used by the heatmap and reports.

This is a small, hand-maintained lookup table covering the techniques ARIA's
tools are wired to emit. It intentionally avoids depending on the full
`mitreattack-python` STIX dataset (multi-MB download, network access) so the
project runs fully offline; swap `TECHNIQUES` for a load from the official
ATT&CK STIX bundle in a production deployment if you want full coverage.
"""

from __future__ import annotations

TECHNIQUES: dict[str, dict[str, str]] = {
    "T1003.001": {"name": "OS Credential Dumping: LSASS Memory", "tactic": "credential-access"},
    "T1021.002": {"name": "Remote Services: SMB/Windows Admin Shares", "tactic": "lateral-movement"},
    "T1021": {"name": "Remote Services", "tactic": "lateral-movement"},
    "T1036.005": {"name": "Masquerading: Match Legitimate Name or Location", "tactic": "defense-evasion"},
    "T1055": {"name": "Process Injection", "tactic": "defense-evasion"},
    "T1059.001": {"name": "Command and Scripting Interpreter: PowerShell", "tactic": "execution"},
    "T1070.006": {"name": "Indicator Removal: Timestomp", "tactic": "defense-evasion"},
    "T1071.001": {"name": "Application Layer Protocol: Web Protocols", "tactic": "command-and-control"},
    "T1071.004": {"name": "Application Layer Protocol: DNS", "tactic": "command-and-control"},
    "T1078": {"name": "Valid Accounts", "tactic": "defense-evasion"},
    "T1078.003": {"name": "Valid Accounts: Local Accounts", "tactic": "privilege-escalation"},
    "T1078.004": {"name": "Valid Accounts: Cloud Accounts", "tactic": "defense-evasion"},
    "T1114.003": {"name": "Email Collection: Email Forwarding Rule", "tactic": "collection"},
    "T1204.002": {"name": "User Execution: Malicious File", "tactic": "execution"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "impact"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "impact"},
    "T1564.008": {"name": "Hide Artifacts: Email Hiding Rules", "tactic": "defense-evasion"},
    "T1568": {"name": "Dynamic Resolution", "tactic": "command-and-control"},
}

TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


def lookup(technique_id: str) -> dict[str, str]:
    return TECHNIQUES.get(technique_id, {"name": technique_id, "tactic": "unknown"})
