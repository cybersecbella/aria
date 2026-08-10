"""Shared helpers for report generation."""

from __future__ import annotations

from typing import Any

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_EMOJI = {"critical": "[CRITICAL]", "high": "[HIGH]", "medium": "[MEDIUM]", "low": "[LOW]", "info": "[INFO]"}


def sorted_findings(state: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(
        state.get("findings", []),
        key=lambda f: (SEVERITY_RANK.get(f.get("severity", "info"), 5), -(f.get("confidence") or 0)),
    )


def severity_counts(state: dict[str, Any]) -> dict[str, int]:
    counts = {k: 0 for k in SEVERITY_RANK}
    for f in state.get("findings", []):
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def timeline(state: dict[str, Any]) -> list[dict[str, Any]]:
    entries = [f for f in state.get("findings", []) if f.get("timestamp")]
    return sorted(entries, key=lambda f: f["timestamp"])


def unique_iocs(state: dict[str, Any]) -> list[str]:
    return sorted(state.get("iocs", set()))


def tools_used(state: dict[str, Any]) -> list[str]:
    return [t["tool"] for t in state.get("tool_runs", []) if t.get("finding_count", 0) >= 0]
