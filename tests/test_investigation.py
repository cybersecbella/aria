"""Smoke tests for the ARIA graph and report pipeline.

Run with: PYTHONPATH=. python3 -m pytest tests/ -q
(or plain `python3 tests/test_investigation.py` -- no pytest dependency required)
"""

from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aria.graph import run_investigation
from aria.state import new_state

SAMPLE_DIR = Path(__file__).resolve().parents[1] / "data" / "sample_incident"


def _artifact(kind, filename):
    return {
        "kind": kind,
        "path": str(SAMPLE_DIR / filename),
        "sha256": "test",
        "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "description": "test artifact",
    }


def test_full_case_runs_all_tools_and_produces_critical_findings():
    artifacts = [
        _artifact("disk", "disk_manifest.json"),
        _artifact("memory", "memory_manifest.json"),
        _artifact("logs", "log_manifest.json"),
        _artifact("pcap", "pcap_manifest.json"),
    ]
    state = new_state("TEST-1", "Test Case", "tester", artifacts, dt.datetime.now(dt.timezone.utc).isoformat())
    result = run_investigation(state)

    assert result["completed_tools"] == {
        "AutoTriage",
        "VolAI",
        "IAM Auditor",
        "AI PCAP Analyst",
        "AI Detection Engineer",
    }
    assert len(result["findings"]) > 10
    assert any(f["severity"] == "critical" for f in result["findings"])
    assert result["attack_techniques"]
    assert result["detection_rules"]


def test_partial_evidence_skips_unavailable_tools():
    artifacts = [_artifact("logs", "log_manifest.json")]
    state = new_state("TEST-2", "Logs Only", "tester", artifacts, dt.datetime.now(dt.timezone.utc).isoformat())
    result = run_investigation(state)

    assert "VolAI" not in result["completed_tools"]
    assert "AI PCAP Analyst" not in result["completed_tools"]
    assert "IAM Auditor" in result["completed_tools"]
    assert "AI Detection Engineer" in result["completed_tools"]


def test_no_artifacts_still_terminates():
    state = new_state("TEST-3", "Empty Case", "tester", [], dt.datetime.now(dt.timezone.utc).isoformat())
    result = run_investigation(state)
    assert result["completed_tools"] == {"AutoTriage", "AI Detection Engineer"}
    assert result["findings"] == []


if __name__ == "__main__":
    test_full_case_runs_all_tools_and_produces_critical_findings()
    test_partial_evidence_skips_unavailable_tools()
    test_no_artifacts_still_terminates()
    print("All smoke tests passed.")
