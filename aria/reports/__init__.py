"""Report package: renders the three audience-specific IR report formats."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aria.reports import executive, legal, technical


def write_all_reports(state: dict[str, Any], output_dir: str) -> dict[str, str]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    paths = {}

    exec_path = out / "executive_brief.md"
    exec_path.write_text(executive.render(state), encoding="utf-8")
    paths["executive"] = str(exec_path)

    tech_path = out / "technical_findings.md"
    tech_path.write_text(technical.render(state), encoding="utf-8")
    paths["technical"] = str(tech_path)

    legal_path = out / "legal_evidence_report.md"
    legal_path.write_text(legal.render(state), encoding="utf-8")
    paths["legal"] = str(legal_path)

    return paths
