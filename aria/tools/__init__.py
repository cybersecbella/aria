"""ARIA analysis tools.

Each module exposes a single `run(state) -> list[Finding]` entrypoint. Tools
never call each other -- they only read/write `IncidentState`. The graph
orchestrator (aria/graph.py) decides which tool runs next by inspecting the
`state["signals"]` dict each tool leaves behind after it runs.
"""

from __future__ import annotations

from typing import Any


def get_artifact_path(state: dict[str, Any], kind: str) -> str | None:
    for artifact in state.get("artifacts", []):
        if artifact.get("kind") == kind:
            return artifact.get("path")
    return None


def make_finding(
    finding_id: str,
    title: str,
    description: str,
    severity: str,
    confidence: float,
    attack_techniques: list[str],
    iocs: list[str] | None = None,
    evidence_refs: list[str] | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "title": title,
        "description": description,
        "severity": severity,
        "confidence": confidence,
        "attack_techniques": attack_techniques,
        "iocs": iocs or [],
        "evidence_refs": evidence_refs or [],
        "timestamp": timestamp,
    }
