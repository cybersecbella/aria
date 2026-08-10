"""IAM Auditor -- identity and access review tool.

Invoked when VolAI (or another tool) confirms credential theft, or whenever
log artifacts are present regardless (cheap to run, high signal). Looks at
sign-in anomalies, over-privileged accounts, and mailbox rule tampering --
the identity-side blast radius of a credential compromise.
"""

from __future__ import annotations

from typing import Any

from aria.ingestion import logs
from aria.tools import get_artifact_path, make_finding

TOOL_NAME = "IAM Auditor"

PRIVILEGED_ROLES = {"Domain Admins", "Enterprise Admins", "Global Administrator"}


def run(state: dict[str, Any]) -> list[dict[str, Any]]:
    path = get_artifact_path(state, "logs")
    findings: list[dict[str, Any]] = []
    signals = state.setdefault("signals", {})

    if not path:
        state["decision_log"].append(f"[{TOOL_NAME}] no log artifact provided, skipping.")
        return findings

    data = logs.ingest(path)
    n = 0

    for event in data["events"]:
        text = event.get("detail", "").lower()
        if "impossible travel" in text:
            n += 1
            signals["identity_compromise"] = True
            findings.append(
                make_finding(
                    f"iam-travel-{n}",
                    f"Impossible travel sign-in for {event.get('user')}",
                    event["detail"],
                    "critical",
                    0.85,
                    ["T1078.004"],
                    evidence_refs=[data["artifact_id"]],
                    timestamp=event.get("time"),
                )
            )
        elif "outside normal hours" in text or ("logon_type" in event and event.get("logon_type") == 3 and "svc_" in event.get("user", "")):
            n += 1
            findings.append(
                make_finding(
                    f"iam-anomlogon-{n}",
                    f"Anomalous service-account logon: {event.get('user')}",
                    event["detail"],
                    "high",
                    0.7,
                    ["T1078.003"],
                    evidence_refs=[data["artifact_id"]],
                    timestamp=event.get("time"),
                )
            )
        elif "inbox rule" in text:
            n += 1
            signals["mailbox_tampering"] = True
            findings.append(
                make_finding(
                    f"iam-mailrule-{n}",
                    f"Malicious inbox rule created by {event.get('user')}",
                    event["detail"],
                    "high",
                    0.8,
                    ["T1114.003", "T1564.008"],
                    evidence_refs=[data["artifact_id"]],
                    timestamp=event.get("time"),
                )
            )
        elif "special privileges assigned" in text:
            n += 1
            findings.append(
                make_finding(
                    f"iam-privesc-{n}",
                    f"Sensitive privileges assigned to {event.get('user')}",
                    event["detail"],
                    "medium",
                    0.6,
                    ["T1078"],
                    evidence_refs=[data["artifact_id"]],
                    timestamp=event.get("time"),
                )
            )

    for identity, profile in data["iam_findings"].items():
        roles = set(profile.get("assigned_roles", []))
        overprivileged = bool(roles & PRIVILEGED_ROLES) and profile.get("type") == "service_account"
        if overprivileged:
            n += 1
            signals["overprivileged_account"] = True
            findings.append(
                make_finding(
                    f"iam-overpriv-{n}",
                    f"Over-privileged service account: {identity}",
                    profile.get("note", f"{identity} holds {', '.join(roles)}"),
                    "high",
                    0.75,
                    ["T1078.003"],
                    evidence_refs=[data["artifact_id"]],
                )
            )
        if profile.get("type") == "service_account" and not profile.get("mfa_enrolled", True):
            n += 1
            findings.append(
                make_finding(
                    f"iam-nomfa-{n}",
                    f"Privileged account without MFA: {identity}",
                    f"{identity} is not enrolled in MFA and holds {', '.join(roles) or 'elevated'} access.",
                    "medium",
                    0.6,
                    ["T1078"],
                    evidence_refs=[data["artifact_id"]],
                )
            )

    if signals.get("identity_compromise") or signals.get("overprivileged_account"):
        signals["needs_detection_engineering"] = True
        state["decision_log"].append(
            f"[{TOOL_NAME}] confirmed identity compromise / over-privileged access -> "
            "flagging for detection engineering once evidence collection completes."
        )

    return findings
