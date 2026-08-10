"""AI PCAP Analyst -- network traffic analysis tool.

Invoked when VolAI observes live beaconing, or when a PCAP artifact is
present. Confirms C2 traffic on the wire, correlates against candidate C2
IPs surfaced by memory analysis, and flags abnormal internal traffic
(e.g. SMB volume spikes consistent with staged exfiltration or mass
encryption reads/writes).
"""

from __future__ import annotations

from typing import Any

from aria.ingestion import pcap
from aria.tools import get_artifact_path, make_finding

TOOL_NAME = "AI PCAP Analyst"

SMB_VOLUME_BYTES_THRESHOLD = 50_000_000


def run(state: dict[str, Any]) -> list[dict[str, Any]]:
    path = get_artifact_path(state, "pcap")
    findings: list[dict[str, Any]] = []
    signals = state.setdefault("signals", {})

    if not path:
        state["decision_log"].append(f"[{TOOL_NAME}] no pcap artifact provided, skipping.")
        return findings

    data = pcap.ingest(path)
    n = 0
    candidate_ips = set(signals.get("c2_candidate_ips", []))

    for flow in data["flows"]:
        note = flow.get("note", "")
        dst = flow.get("dst")
        if dst in candidate_ips or "c2" in note.lower() or "ja3" in note.lower():
            n += 1
            signals["c2_confirmed"] = True
            findings.append(
                make_finding(
                    f"pcap-c2-{n}",
                    f"C2 traffic confirmed: {flow['src']} -> {dst}:{flow.get('dport')}",
                    note,
                    "critical",
                    0.9,
                    ["T1071.001", "T1568"],
                    iocs=[dst] if dst else [],
                    evidence_refs=[data["artifact_id"]],
                )
            )
        elif flow.get("proto") == "SMB" and flow.get("bytes", 0) > SMB_VOLUME_BYTES_THRESHOLD:
            n += 1
            signals["abnormal_internal_transfer"] = True
            findings.append(
                make_finding(
                    f"pcap-smb-{n}",
                    f"Abnormal SMB volume: {flow['src']} -> {flow['dst']}",
                    note or f"{flow['bytes']:,} bytes across {flow.get('packets', 0):,} packets",
                    "high",
                    0.65,
                    ["T1021.002", "T1486"],
                    evidence_refs=[data["artifact_id"]],
                )
            )
        elif flow.get("proto") == "DNS" and any("onion" in q for q in flow.get("queries", [])):
            n += 1
            findings.append(
                make_finding(
                    f"pcap-dns-{n}",
                    "DNS lookup for Tor gateway / onion domain",
                    note,
                    "medium",
                    0.6,
                    ["T1071.004"],
                    evidence_refs=[data["artifact_id"]],
                )
            )

    for alert in data["alerts"]:
        n += 1
        sev = alert.get("severity", "medium")
        findings.append(
            make_finding(
                f"pcap-alert-{n}",
                alert.get("signature", "IDS alert"),
                f"{alert.get('src')} -> {alert.get('dst')}",
                sev,
                0.7,
                ["T1071.001"],
                evidence_refs=[data["artifact_id"]],
            )
        )

    signals["needs_detection_engineering"] = True
    state["decision_log"].append(
        f"[{TOOL_NAME}] traffic analysis complete -> flagging for detection engineering."
    )

    return findings
