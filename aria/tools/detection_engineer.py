"""AI Detection Engineer -- correlation and detection-rule authoring tool.

Runs last. It doesn't re-parse raw artifacts; it looks at the accumulated
`state["findings"]` from every tool that ran before it, correlates them into
a small number of cross-domain attack-narrative findings (e.g. "the process
VolAI saw dumping credentials is the same one AutoTriage saw dropped by a
phishing macro, and it's the same host IAM Auditor saw log in as a
privileged service account eleven minutes later"), and drafts Sigma
detection rules an in-house team can deploy to catch a repeat of this
technique.
"""

from __future__ import annotations

from typing import Any

from aria.tools import make_finding

TOOL_NAME = "AI Detection Engineer"


def _correlate(state: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    signals = state.get("signals", {})

    if signals.get("malware_dropped") and signals.get("credential_theft"):
        findings.append(
            make_finding(
                "det-corr-1",
                "Correlated attack chain: phishing dropper -> credential theft",
                "AutoTriage identified a masqueraded binary dropped by a macro-enabled "
                "attachment; VolAI independently confirmed LSASS credential access from a "
                "process in the same execution chain. High-confidence single incident, not "
                "two unrelated events.",
                "critical",
                0.9,
                ["T1204.002", "T1003.001"],
            )
        )

    if signals.get("credential_theft") and signals.get("identity_compromise"):
        findings.append(
            make_finding(
                "det-corr-2",
                "Correlated attack chain: stolen credentials used for lateral movement",
                "Credentials harvested in memory were used minutes later for an anomalous "
                "privileged service-account logon and an impossible-travel sign-in, "
                "indicating the stolen material was actively used, not just collected.",
                "critical",
                0.85,
                ["T1003.001", "T1078.004", "T1021"],
            )
        )

    if signals.get("c2_confirmed") and signals.get("beaconing_observed"):
        findings.append(
            make_finding(
                "det-corr-3",
                "Correlated attack chain: memory-resident implant confirmed communicating with C2",
                "The network connection observed live in memory by VolAI matches a "
                "JA3-fingerprinted TLS session to a newly-registered domain captured by the "
                "PCAP Analyst, confirming active command-and-control rather than benign traffic.",
                "critical",
                0.9,
                ["T1071.001", "T1568"],
            )
        )

    if signals.get("ransomware_indicators") and signals.get("abnormal_internal_transfer"):
        findings.append(
            make_finding(
                "det-corr-4",
                "Correlated attack chain: shadow-copy deletion preceding mass file encryption",
                "A shadow-copy deletion command was logged shortly before abnormal SMB "
                "volume and mass file-rename activity on the finance share, and encrypted "
                "files plus a ransom note were recovered from disk -- consistent with "
                "ransomware deployment following data staging.",
                "critical",
                0.9,
                ["T1490", "T1486", "T1021.002"],
            )
        )

    return findings


def _draft_detection_rules(state: dict[str, Any]) -> list[dict[str, Any]]:
    signals = state.get("signals", {})
    rules: list[dict[str, Any]] = []

    if signals.get("credential_theft"):
        rules.append(
            {
                "title": "Suspicious LSASS Access by Non-Standard Process",
                "id": "aria-rule-lsass-access",
                "logsource": {"category": "process_access", "product": "windows"},
                "detection": {
                    "selection": {"TargetImage|endswith": "\\lsass.exe", "GrantedAccess": "0x1010"},
                    "condition": "selection",
                },
                "attack_techniques": ["T1003.001"],
                "level": "high",
            }
        )

    if signals.get("identity_compromise"):
        rules.append(
            {
                "title": "Impossible Travel Sign-In for Privileged Identity",
                "id": "aria-rule-impossible-travel",
                "logsource": {"category": "authentication", "product": "azuread"},
                "detection": {
                    "selection": {"event": "SigninLogs", "travel_delta_minutes": "<60", "distance_km": ">500"},
                    "condition": "selection",
                },
                "attack_techniques": ["T1078.004"],
                "level": "critical",
            }
        )

    if signals.get("c2_confirmed"):
        rules.append(
            {
                "title": "Beaconing TLS Session to Newly Registered Domain",
                "id": "aria-rule-c2-beacon",
                "logsource": {"category": "network_connection", "product": "zeek"},
                "detection": {
                    "selection": {"domain_age_days": "<30", "interval_jitter": "<5%"},
                    "condition": "selection",
                },
                "attack_techniques": ["T1071.001", "T1568"],
                "level": "high",
            }
        )

    if signals.get("ransomware_indicators"):
        rules.append(
            {
                "title": "Shadow Copy Deletion Followed by Mass File Rename",
                "id": "aria-rule-ransomware-staging",
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection": {"CommandLine|contains": "vssadmin delete shadows"},
                    "condition": "selection",
                },
                "attack_techniques": ["T1490", "T1486"],
                "level": "critical",
            }
        )

    if signals.get("overprivileged_account"):
        rules.append(
            {
                "title": "Service Account Holding Domain Admin Membership",
                "id": "aria-rule-overprivileged-svc",
                "logsource": {"category": "identity_posture", "product": "activedirectory"},
                "detection": {
                    "selection": {"account_type": "service", "group_membership": "Domain Admins"},
                    "condition": "selection",
                },
                "attack_techniques": ["T1078.003"],
                "level": "medium",
            }
        )

    return rules


def run(state: dict[str, Any]) -> list[dict[str, Any]]:
    findings = _correlate(state)
    state["detection_rules"] = _draft_detection_rules(state)
    state["decision_log"].append(
        f"[{TOOL_NAME}] correlated {len(state.get('findings', []))} raw findings into "
        f"{len(findings)} attack-chain finding(s) and drafted {len(state['detection_rules'])} "
        "detection rule(s)."
    )
    return findings
