"""Memory dump ingestion.

Production notes
-----------------
A real backend would drive Volatility 3 (pslist/pstree, malfind, ldrmodules,
handles, netscan) against the raw memory image. That requires the actual
Volatility3 framework and a matching OS profile/symbol table, which we don't
have here, so this module reads a pre-extracted manifest shaped like the
consolidated output of those plugins: suspicious processes, LSASS access
events, malfind hits, live network connections, and carved strings.

Swap-in point: replace `load_memory_manifest` with calls into
`volatility3.framework` (see the VolAI tool this project name-checks) and
normalize plugin output into this same shape.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_memory_manifest(manifest_path: str) -> dict[str, Any]:
    with open(manifest_path, encoding="utf-8") as fh:
        return json.load(fh)


def normalize(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "artifact_id": manifest.get("artifact_id"),
        "suspicious_processes": manifest.get("suspicious_processes", []),
        "lsass_access": manifest.get("lsass_access", []),
        "network_connections": manifest.get("network_connections", []),
        "malfind_hits": manifest.get("malfind_hits", []),
        "extracted_strings": manifest.get("extracted_strings", []),
    }


def ingest(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Memory manifest not found: {path}")
    return normalize(load_memory_manifest(str(p)))
