"""AutoTriage -- first responder tool.

Runs against the disk image manifest to answer one question fast: is there
something here worth escalating, and if so, what should ARIA look at next?
This is deliberately the first node in the graph for every case -- it sets
the initial signals that decide whether memory, IAM, or PCAP analysis even
need to run.
"""

from __future__ import annotations

from typing import Any

from aria.ingestion import disk
from aria.tools import get_artifact_path, make_finding

TOOL_NAME = "AutoTriage"


def run(state: dict[str, Any]) -> list[dict[str, Any]]:
    path = get_artifact_path(state, "disk")
    findings: list[dict[str, Any]] = []
    signals = state.setdefault("signals", {})

    if not path:
        state["decision_log"].append(f"[{TOOL_NAME}] no disk artifact provided, skipping.")
        return findings

    data = disk.ingest(path)
    n = 0

    for f in data["suspicious_files"]:
        n += 1
        is_dropper = "svch0st" in f["path"].lower() or "temp" in f["path"].lower()
        findings.append(
            make_finding(
                f"autotriage-file-{n}",
                f"Suspicious file: {f['path']}",
                f.get("note", "Flagged during disk triage."),
                "high" if is_dropper else "medium",
                0.8 if is_dropper else 0.5,
                ["T1204.002", "T1036.005"] if is_dropper else ["T1486"],
                iocs=[f.get("sha256", "")],
                evidence_refs=[data["artifact_id"]],
            )
        )
        if is_dropper:
            signals["malware_dropped"] = True

    for note in data["ransom_notes"]:
        n += 1
        signals["ransomware_indicators"] = True
        findings.append(
            make_finding(
                f"autotriage-ransom-{n}",
                "Ransom note recovered",
                note.get("excerpt", ""),
                "critical",
                0.95,
                ["T1486", "T1490"],
                evidence_refs=[data["artifact_id"]],
                timestamp=note.get("created"),
            )
        )

    for anomaly in data["mft_anomalies"]:
        if anomaly.get("timestomp_detected"):
            n += 1
            signals["anti_forensics"] = True
            findings.append(
                make_finding(
                    f"autotriage-timestomp-{n}",
                    f"Timestomping detected: {anomaly['path']}",
                    anomaly.get("note", ""),
                    "high",
                    0.75,
                    ["T1070.006"],
                    evidence_refs=[data["artifact_id"]],
                )
            )

    exec_evidence = [p for p in data["prefetch"] if p.get("run_count", 0) > 0]
    if exec_evidence:
        signals["execution_confirmed"] = True

    # Routing decision: any sign of malware/ransomware means we need to see
    # what was actually running in memory when this happened.
    if signals.get("malware_dropped") or signals.get("ransomware_indicators"):
        signals["needs_memory_analysis"] = True
        state["decision_log"].append(
            f"[{TOOL_NAME}] malware/ransomware indicators on disk -> routing to VolAI for memory analysis."
        )
    else:
        state["decision_log"].append(f"[{TOOL_NAME}] no strong malware signal on disk; may skip memory analysis.")

    return findings
