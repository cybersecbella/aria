"""Packet capture ingestion.

Production notes
-----------------
A real backend would run this through Zeek and/or Suricata (conn.log,
dns.log, ssl.log + ET/Sigma-style alerting), or use `pyshark`/`scapy` for
targeted flow extraction and JA3 fingerprinting. That requires the actual
capture engines, so this module reads a pre-extracted manifest shaped like a
Zeek+Suricata fusion output: per-flow metadata (bytes, packets, SNI, JA3
notes) plus a signature-alert list.

Swap-in point: replace `load_pcap_manifest` with Zeek/Suricata invocation +
log parsing that emits `{"flows": [...], "alerts": [...]}`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_pcap_manifest(manifest_path: str) -> dict[str, Any]:
    with open(manifest_path, encoding="utf-8") as fh:
        return json.load(fh)


def normalize(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "artifact_id": manifest.get("artifact_id"),
        "duration_seconds": manifest.get("duration_seconds"),
        "flows": manifest.get("flows", []),
        "alerts": manifest.get("alerts", []),
    }


def ingest(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"PCAP manifest not found: {path}")
    return normalize(load_pcap_manifest(str(p)))
