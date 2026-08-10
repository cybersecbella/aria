"""Shared state schema passed between every node in the ARIA LangGraph graph.

Every tool node reads from and writes to this single state object. Nodes never
call each other directly -- the graph's conditional-edge functions inspect
`state["findings"]` / `state["signals"]` after each node runs and decide what
runs next. This is what makes ARIA a decision-driven agent rather than a
fixed pipeline: the same case can take a completely different path through
the graph depending on what AutoTriage finds in the first thirty seconds.
"""

from __future__ import annotations

from typing import Any, Literal, TypedDict

Severity = Literal["info", "low", "medium", "high", "critical"]


class Artifact(TypedDict, total=False):
    """A single piece of raw evidence provided to ARIA on the CLI."""

    kind: Literal["disk", "memory", "logs", "pcap"]
    path: str
    sha256: str
    collected_at: str
    description: str


class Finding(TypedDict, total=False):
    """A normalized finding emitted by any analysis tool node."""

    id: str
    source_tool: str
    title: str
    description: str
    severity: Severity
    confidence: float
    attack_techniques: list[str]  # e.g. ["T1059.001", "T1078"]
    iocs: list[str]
    evidence_refs: list[str]  # artifact ids / offsets / log line ids this rests on
    timestamp: str | None


class ToolRun(TypedDict, total=False):
    """Audit trail entry: which tool ran, why, and what it produced."""

    tool: str
    reason: str
    started_at: str
    finished_at: str
    finding_count: int


class IncidentState(TypedDict, total=False):
    # --- case metadata ---
    case_id: str
    case_name: str
    analyst: str
    started_at: str

    # --- inputs ---
    artifacts: list[Artifact]

    # --- routing signals the orchestrator inspects to pick the next tool ---
    signals: dict[str, Any]

    # --- accumulated output ---
    findings: list[Finding]
    iocs: set[str]
    attack_techniques: dict[str, int]  # technique_id -> occurrence count
    tool_runs: list[ToolRun]
    decision_log: list[str]  # human-readable trace of orchestrator reasoning

    # --- which tools have already run, so the graph doesn't loop forever ---
    completed_tools: set[str]
    pending_tools: list[str]

    # --- detection engineering output ---
    detection_rules: list[dict[str, Any]]

    # --- final artifacts ---
    heatmap_layer_path: str | None
    heatmap_html_path: str | None
    report_paths: dict[str, str]


def new_state(
    case_id: str,
    case_name: str,
    analyst: str,
    artifacts: list[Artifact],
    started_at: str,
) -> IncidentState:
    return IncidentState(
        case_id=case_id,
        case_name=case_name,
        analyst=analyst,
        started_at=started_at,
        artifacts=artifacts,
        signals={},
        findings=[],
        iocs=set(),
        attack_techniques={},
        tool_runs=[],
        decision_log=[f"Case {case_id} opened for {case_name} with {len(artifacts)} artifact(s)."],
        completed_tools=set(),
        pending_tools=[],
        detection_rules=[],
        heatmap_layer_path=None,
        heatmap_html_path=None,
        report_paths={},
    )


def record_findings(state: IncidentState, tool: str, findings: list[Finding]) -> None:
    """Merge a tool's findings into the shared state, updating derived signals."""

    for f in findings:
        f.setdefault("source_tool", tool)
        state["findings"].append(f)
        for ioc in f.get("iocs", []):
            state["iocs"].add(ioc)
        for tech in f.get("attack_techniques", []):
            state["attack_techniques"][tech] = state["attack_techniques"].get(tech, 0) + 1

    state["completed_tools"].add(tool)
