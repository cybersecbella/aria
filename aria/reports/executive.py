"""Executive brief -- written for a CEO/board audience.

No technique IDs, no jargon in the body. Business impact, what happened,
what ARIA/the response team did about it, and what's needed next.
"""

from __future__ import annotations

from typing import Any

from aria.reports.common import severity_counts, sorted_findings, unique_iocs

_IMPACT_STATEMENTS = {
    "ransomware_indicators": "Data on at least one file server was encrypted by ransomware.",
    "credential_theft": "Employee or service account credentials were stolen from a compromised workstation.",
    "identity_compromise": "A privileged account was used from an unexpected location, indicating account takeover.",
    "c2_confirmed": "The attacker maintained an active remote-control channel into the network.",
    "abnormal_internal_transfer": "A large volume of data was moved internally in a way consistent with staged theft or mass encryption.",
    "mailbox_tampering": "An email inbox rule was created to silently intercept and delete sensitive messages, consistent with financial fraud (e.g. wire transfer interception).",
}


def render(state: dict[str, Any]) -> str:
    counts = severity_counts(state)
    findings = sorted_findings(state)
    top = [f for f in findings if f.get("severity") in ("critical", "high")][:5]
    signals = state.get("signals", {})

    impacts = [msg for key, msg in _IMPACT_STATEMENTS.items() if signals.get(key)]

    lines: list[str] = []
    lines.append(f"# Executive Incident Brief -- {state.get('case_name', 'Untitled Case')}")
    lines.append("")
    lines.append(f"**Case ID:** {state.get('case_id', 'N/A')}  ")
    lines.append(f"**Prepared for:** Executive leadership / Board  ")
    lines.append(f"**Prepared by:** ARIA (AI Response & Investigation Agent), reviewed by {state.get('analyst', 'IR Analyst')}  ")
    lines.append(f"**Case opened:** {state.get('started_at', '')}")
    lines.append("")
    lines.append("## Bottom Line")
    lines.append("")
    if counts["critical"] > 0:
        lines.append(
            f"This was a **confirmed security incident** with {counts['critical']} critical-severity finding(s). "
            "Immediate containment and recovery actions are underway or required."
        )
    elif counts["high"] > 0:
        lines.append(
            f"This was a **significant security event** with {counts['high']} high-severity finding(s) requiring prompt remediation."
        )
    else:
        lines.append("Investigation found no critical or high-severity confirmed impact based on the evidence reviewed.")
    lines.append("")

    if impacts:
        lines.append("## What Happened, in Plain Terms")
        lines.append("")
        for msg in impacts:
            lines.append(f"- {msg}")
        lines.append("")

    lines.append("## Business Impact Summary")
    lines.append("")
    lines.append(f"- **{counts['critical']}** critical-severity findings")
    lines.append(f"- **{counts['high']}** high-severity findings")
    lines.append(f"- **{len(unique_iocs(state))}** distinct indicators of compromise identified")
    lines.append(f"- **{len(state.get('attack_techniques', {}))}** distinct attacker techniques observed (see ATT&CK heatmap)")
    lines.append("")

    if top:
        lines.append("## Key Findings")
        lines.append("")
        for f in top:
            lines.append(f"- **{f.get('title')}.** {f.get('description')}")
        lines.append("")

    lines.append("## What ARIA Did")
    lines.append("")
    lines.append(
        "ARIA autonomously ingested the disk image, memory capture, log bundle, and network capture collected "
        "for this incident, and ran an AI-orchestrated investigation -- automatically deciding which specialist "
        "tools (malware triage, memory forensics, identity audit, network analysis, detection engineering) to "
        "invoke based on what each prior step found, rather than running a fixed checklist. This reduces the "
        "manual triage phase of an investigation like this from days to hours."
    )
    lines.append("")
    lines.append("## Recommended Next Steps")
    lines.append("")
    lines.append("1. Review and approve the containment/eradication actions in the accompanying technical report.")
    lines.append("2. Reset credentials and revoke sessions for every identity referenced in this brief.")
    lines.append("3. Confirm whether regulatory or client notification obligations apply, in consultation with legal counsel.")
    lines.append("4. Track remediation of the detection gaps identified in the technical report to prevent recurrence.")
    lines.append("")
    lines.append("*This brief was generated automatically. All underlying findings are reproducible from the evidence referenced in the technical and legal reports.*")

    return "\n".join(lines)
