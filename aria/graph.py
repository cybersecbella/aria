"""LangGraph orchestration for ARIA.

This is the piece that makes ARIA an *agent* rather than a fixed pipeline:
after every analysis tool runs, `decide_next` inspects the signals that tool
left in shared state and picks whichever remaining tool is highest priority
given what's been found so far -- or decides the case is ready for detection
engineering and reporting. Two cases with identical inputs but different
findings can take entirely different paths through this graph.

Uses the real `langgraph.graph.StateGraph` when the package is installed
(see requirements.txt). Falls back to a tiny drop-in shim
(`aria._graph_compat`) with an identical API when it isn't, so this file
never has to branch on which one is active.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

try:
    from langgraph.graph import END, StateGraph  # type: ignore
except ImportError:  # pragma: no cover - exercised in sandboxes without network access
    from aria._graph_compat import END, StateGraph

from aria.state import IncidentState, record_findings
from aria.tools import autotriage, detection_engineer, iam_auditor, pcap_analyst, volai

NODE_AUTOTRIAGE = "AutoTriage"
NODE_VOLAI = "VolAI"
NODE_IAM = "IAM Auditor"
NODE_PCAP = "AI PCAP Analyst"
NODE_DETECTION = "AI Detection Engineer"

_TOOL_MODULES = {
    NODE_AUTOTRIAGE: autotriage,
    NODE_VOLAI: volai,
    NODE_IAM: iam_auditor,
    NODE_PCAP: pcap_analyst,
    NODE_DETECTION: detection_engineer,
}


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _make_node(tool_name: str):
    module = _TOOL_MODULES[tool_name]

    def _node(state: IncidentState) -> IncidentState:
        started = _now()
        findings = module.run(state)
        record_findings(state, tool_name, findings)
        state["tool_runs"].append(
            {
                "tool": tool_name,
                "reason": _reason_for(tool_name, state),
                "started_at": started,
                "finished_at": _now(),
                "finding_count": len(findings),
            }
        )
        return state

    return _node


def _reason_for(tool_name: str, state: IncidentState) -> str:
    if tool_name == NODE_AUTOTRIAGE:
        return "Always runs first: cheapest signal source, decides what else is worth analyzing."
    signals = state.get("signals", {})
    if tool_name == NODE_VOLAI:
        return "Disk triage flagged malware/ransomware indicators requiring memory analysis." \
            if signals.get("needs_memory_analysis") else "Memory artifact available for baseline review."
    if tool_name == NODE_IAM:
        return "Credential theft or identity signal detected upstream; auditing account abuse." \
            if signals.get("credential_theft") or signals.get("needs_iam_audit") else "Log artifact available for identity review."
    if tool_name == NODE_PCAP:
        return "Live beaconing observed in memory; confirming C2 on the wire." \
            if signals.get("needs_pcap_analysis") else "PCAP artifact available for network review."
    if tool_name == NODE_DETECTION:
        return "All available evidence sources exhausted; correlating findings and drafting detections."
    return "Selected by orchestrator."


def _has_artifact(state: IncidentState, kind: str) -> bool:
    return any(a.get("kind") == kind for a in state.get("artifacts", []))


def decide_next(state: IncidentState) -> str:
    """The orchestrator's routing brain.

    Priority is driven by the signals tools leave behind, not by artifact
    order or a hardcoded sequence. A case with no ransomware indicators on
    disk might skip memory analysis entirely; a case with no credential
    theft signal might still run IAM Auditor cheaply if logs are present,
    but at lower priority than a case where VolAI explicitly asked for it.
    """

    signals = state.get("signals", {})
    completed = state.get("completed_tools", set())

    candidates: list[tuple[str, int]] = []

    if NODE_VOLAI not in completed and _has_artifact(state, "memory"):
        priority = 3 if signals.get("needs_memory_analysis") else 1
        candidates.append((NODE_VOLAI, priority))

    if NODE_IAM not in completed and _has_artifact(state, "logs"):
        priority = 3 if (signals.get("needs_iam_audit") or signals.get("credential_theft")) else 1
        candidates.append((NODE_IAM, priority))

    if NODE_PCAP not in completed and _has_artifact(state, "pcap"):
        priority = 3 if signals.get("needs_pcap_analysis") else 1
        candidates.append((NODE_PCAP, priority))

    if candidates:
        candidates.sort(key=lambda c: -c[1])
        next_tool, priority = candidates[0]
        state["decision_log"].append(
            f"[orchestrator] routing to {next_tool} (priority {priority}); "
            f"remaining candidates: {[c[0] for c in candidates[1:]]}"
        )
        return next_tool

    if NODE_DETECTION not in completed:
        state["decision_log"].append(
            "[orchestrator] no evidence-gathering tools remain -- routing to AI Detection Engineer "
            "for correlation and rule drafting."
        )
        return NODE_DETECTION

    state["decision_log"].append("[orchestrator] investigation complete.")
    return "END"


def build_graph():
    graph = StateGraph(IncidentState)

    for name in _TOOL_MODULES:
        graph.add_node(name, _make_node(name))

    graph.set_entry_point(NODE_AUTOTRIAGE)

    routing_map = {
        NODE_VOLAI: NODE_VOLAI,
        NODE_IAM: NODE_IAM,
        NODE_PCAP: NODE_PCAP,
        NODE_DETECTION: NODE_DETECTION,
        "END": END,
    }

    for node in (NODE_AUTOTRIAGE, NODE_VOLAI, NODE_IAM, NODE_PCAP):
        graph.add_conditional_edges(node, decide_next, routing_map)

    graph.add_edge(NODE_DETECTION, END)

    return graph.compile()


def run_investigation(state: IncidentState) -> IncidentState:
    """Compile and run the graph once for a single case."""

    compiled = build_graph()
    result: Any = compiled.invoke(state)
    return result
