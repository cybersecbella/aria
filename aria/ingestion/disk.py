"""Disk image ingestion.

Production notes
-----------------
In a real deployment this module would shell out to The Sleuth Kit / pytsk3
(fls, istat, icat) or a commercial acquisition suite to walk the filesystem,
carve the MFT, and pull hashes + timestamps for files of interest. That is
outside what this sandbox can safely execute against a raw .E01/.dd image, so
this module instead reads a pre-extracted JSON "manifest" that represents
exactly the shape of data a TSK-based extractor would hand back: suspicious
files, ransom notes, MFT timestomping flags, and Prefetch execution records.

Swap-in point: replace `load_disk_manifest` with a function that runs
`pytsk3` / `dfvfs` against `artifact["path"]` and emits the same dict shape.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_disk_manifest(manifest_path: str) -> dict[str, Any]:
    with open(manifest_path, encoding="utf-8") as fh:
        return json.load(fh)


def normalize(manifest: dict[str, Any]) -> dict[str, Any]:
    """Reduce the raw manifest to the fields analysis tools actually need."""

    return {
        "artifact_id": manifest.get("artifact_id"),
        "suspicious_files": manifest.get("suspicious_files", []),
        "ransom_notes": manifest.get("ransom_notes", []),
        "mft_anomalies": manifest.get("mft_anomalies", []),
        "prefetch": manifest.get("prefetch", []),
    }


def ingest(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Disk manifest not found: {path}")
    return normalize(load_disk_manifest(str(p)))
