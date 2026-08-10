"""VolAI -- AI-assisted memory forensics tool.

Invoked only when AutoTriage (or another tool) sets `needs_memory_analysis`.
Looks at what was actually resident in RAM: process trees, LSASS handle
access (credential dumping), injected memory regions, and live network
connections. This tool is what typically confirms or rules out credential
theft, and it's what hands the C2 IP to the PCAP analyst.
"""

from __future__ import annotations

from typing import Any

from aria.ingestion import memory
from aria.tools import get_artifact_path, make_finding

TOOL_NAME = "VolAI"


def run(state: dict[str, Any]) -> list[dict[str, Any]]:
    path = get_artifact_path(state, "memory")
    findings: list[dict[str, Any]] = []
    signals = state.setdefault("signals", {})

    if not path:
        state["decision_log"].append(f"[{TOOL_NAME}] no memory artifact provided, skipping.")
        return findings

    data = memory.ingest(path)
    n = 0

    for proc in data["suspicious_processes"]:
        n += 1
        findings.append(
            make_finding(
                f"volai-proc-{n}",
                f"Suspicious process: {proc['name']} (pid {proc['pid']})",
                proc.get("note", proc.get("cmdline", "")),
                "high",
                0.8,
                ["T1055"] if "inject" in proc.get("note", "").lower() else ["T1059.001"],
                evidence_refs=[data["artifact_id"]],
            )
        )

    if data["lsass_access"]:
        signals["credential_theft"] = True
        for acc in data["lsass_access"]:
            n += 1
            findings.append(
                make_finding(
                    f"volai-lsass-{n}",
                    "LSASS memory access consistent with credential dumping",
                    acc.get("note", ""),
                    "critical",
                    0.9,
                    ["T1003.001"],
                    evidence_refs=[data["artifact_id"]],
                )
            )

    for hit in data["malfind_hits"]:
        n += 1
        signals["process_injection"] = True
        findings.append(
            make_finding(
                f"volai-malfind-{n}",
                f"Injected memory region in pid {hit['pid']}",
                hit.get("note", ""),
                "high",
                0.75,
                ["T1055"],
                evidence_refs=[data["artifact_id"]],
            )
        )

    for conn in data["network_connections"]:
        n += 1
        signals.setdefault("c2_candidate_ips", [])
        remote_ip = conn["remote"].split(":")[0]
        signals["c2_candidate_ips"].append(remote_ip)
        signals["beaconing_observed"] = True
        findings.append(
            make_finding(
                f"volai-net-{n}",
                f"Live connection from pid {conn['pid']} to {conn['remote']}",
                conn.get("note", ""),
                "high",
                0.7,
                ["T1071.001"],
                iocs=[remote_ip],
                evidence_refs=[data["artifact_id"]],
            )
        )

    if any("sekurlsa" in s for s in data["extracted_strings"]):
        signals["credential_theft"] = True

    # Routing decisions.
    if signals.get("credential_theft"):
        signals["needs_iam_audit"] = True
        state["decision_log"].append(
            f"[{TOOL_NAME}] credential dumping confirmed in memory -> routing to IAM Auditor "
            "to check for downstream account abuse."
        )
    if signals.get("beaconing_observed"):
        signals["needs_pcap_analysis"] = True
        state["decision_log"].append(
            f"[{TOOL_NAME}] live C2-style connection observed -> routing to AI PCAP Analyst "
            "to confirm on the wire."
        )

    return findings
