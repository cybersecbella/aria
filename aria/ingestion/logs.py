"""Log bundle ingestion (Windows Event Log, cloud IdP sign-in logs, SaaS audit logs).

Production notes
-----------------
A real backend would parse .evtx via `python-evtx` / `Chainsaw`, pull Azure AD
/ Okta sign-in logs via their APIs, and normalize everything into a common
timeline (this is exactly what AutoTriage and the IAM Auditor tools this
project builds on do today). Here we read a pre-normalized JSON manifest with
the same event shape those parsers produce, plus a per-identity IAM summary
block (roles, MFA status, password age) that the IAM Auditor tool consumes.

Swap-in point: replace `load_log_manifest` with real EVTX/API parsing that
emits `{"events": [...], "iam_findings": {...}}`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_log_manifest(manifest_path: str) -> dict[str, Any]:
    with open(manifest_path, encoding="utf-8") as fh:
        return json.load(fh)


def normalize(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "artifact_id": manifest.get("artifact_id"),
        "sources": manifest.get("sources", []),
        "events": manifest.get("events", []),
        "iam_findings": manifest.get("iam_findings", {}),
    }


def ingest(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Log manifest not found: {path}")
    return normalize(load_log_manifest(str(p)))
