"""Legal evidence report -- written for litigation / law-enforcement / regulator handoff.

Conservative language throughout: findings are stated as "the evidence shows"
rather than interpreted or speculated on. Every finding carries its evidence
reference and confidence score. Chain-of-custody and artifact integrity
(hashes) are documented explicitly, since this document may need to support
admissibility of the underlying evidence.

This is a template for a forensic report exhibit, not a substitute for legal
review -- have counsel review before any external production.
"""

from __future__ import annotations

from typing import Any

from aria.reports.common import sorted_findings, unique_iocs


def render(state: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"# Forensic Evidence Report -- {state.get('case_name', 'Untitled Case')}")
    lines.append("")
    lines.append(f"**Case ID:** {state.get('case_id')}  ")
    lines.append(f"**Examiner of record:** {state.get('analyst')}  ")
    lines.append(f"**Analysis system:** ARIA v0.1.0 (AI-assisted, examiner-reviewed)  ")
    lines.append(f"**Report generated:** {state.get('started_at')}")
    lines.append("")
    lines.append(
        "> **Notice.** This report was produced with AI-assisted analysis tools and is intended to support, "
        "not replace, examiner judgment and legal review. All findings below reference the specific evidence "
        "item and confidence level on which they rest. This document is a template exhibit and should be "
        "reviewed by counsel before production or testimony."
    )
    lines.append("")

    lines.append("## 1. Evidence Inventory and Chain of Custody")
    lines.append("")
    lines.append("| Artifact ID | Type | Path/Reference | SHA-256 | Collected | Description |")
    lines.append("|---|---|---|---|---|---|")
    for a in state.get("artifacts", []):
        lines.append(
            f"| {a.get('kind')}-evidence | {a.get('kind')} | `{a.get('path')}` | "
            f"`{a.get('sha256', 'not recorded')}` | {a.get('collected_at', 'not recorded')} | {a.get('description', '')} |"
        )
    lines.append("")
    lines.append(
        "All artifacts listed above were ingested read-only by ARIA's analysis tools. No modification was made "
        "to source evidence during automated analysis. Hash values should be independently verified against the "
        "original acquisition hash before this report is relied upon."
    )
    lines.append("")

    lines.append("## 2. Methodology")
    lines.append("")
    lines.append(
        "ARIA performed an AI-orchestrated examination using the following analysis modules, invoked "
        "adaptively based on findings at each stage (full decision rationale in Section 5):"
    )
    lines.append("")
    for run in state.get("tool_runs", []):
        lines.append(f"- **{run['tool']}** -- invoked because: {run.get('reason', '')}")
    lines.append("")

    lines.append("## 3. Findings")
    lines.append("")
    lines.append(
        "Each finding below is stated with its supporting evidence reference and the examiner-tool's confidence "
        "score (0.0-1.0). Findings below a confidence of 0.6 are noted as such and should be independently "
        "corroborated before being relied upon in any legal proceeding."
    )
    lines.append("")
    for i, f in enumerate(sorted_findings(state), start=1):
        confidence = f.get("confidence") or 0
        caveat = " *(low confidence -- recommend independent corroboration)*" if confidence < 0.6 else ""
        lines.append(f"**Finding {i}.** {f.get('title')}.{caveat}")
        lines.append("")
        lines.append(f"- Observation: {f.get('description')}")
        lines.append(f"- Supporting evidence: {', '.join(f.get('evidence_refs', [])) or 'not specified'}")
        lines.append(f"- Analysis confidence: {confidence}")
        if f.get("timestamp"):
            lines.append(f"- Associated timestamp: {f.get('timestamp')} (source clock, not independently normalized to UTC unless noted)")
        lines.append(f"- Analysis module: {f.get('source_tool')}")
        lines.append("")

    iocs = unique_iocs(state)
    if iocs:
        lines.append("## 4. Indicators of Compromise (for exhibit reference)")
        lines.append("")
        for ioc in iocs:
            lines.append(f"- `{ioc}`")
        lines.append("")

    lines.append("## 5. Examiner Decision Log")
    lines.append("")
    lines.append(
        "The following is the complete, unedited decision trail produced by the analysis system, preserved for "
        "transparency and reproducibility:"
    )
    lines.append("")
    for entry in state.get("decision_log", []):
        lines.append(f"- {entry}")
    lines.append("")

    lines.append("## 6. Examiner Attestation")
    lines.append("")
    lines.append(
        f"I, {state.get('analyst', '[Examiner Name]')}, reviewed the automated findings above against the "
        "source evidence and attest to their accuracy as of the date of this report, subject to the caveats "
        "noted herein. Signature: ________________________  Date: ________________"
    )

    return "\n".join(lines)
