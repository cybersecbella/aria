"""Minimal LangGraph-API-compatible shim.

ARIA is written against the real `langgraph.graph.StateGraph` API
(`add_node`, `add_edge`, `add_conditional_edges`, `set_entry_point`,
`compile().invoke(...)`). When `langgraph` is installed (see
requirements.txt), `aria/graph.py` uses it directly.

This module exists purely so the project can be exercised in environments
where `pip install langgraph` isn't possible (e.g. network-restricted CI
sandboxes) without changing a single line of orchestration logic in
`graph.py`. It implements the small subset of the API ARIA actually uses.
Do not extend this file with new LangGraph features -- add them to a real
`langgraph` dependency instead; this shim is a fallback, not a fork.
"""

from __future__ import annotations

from typing import Any, Callable

END = "__end__"
START = "__start__"


class CompiledGraph:
    def __init__(self, nodes: dict[str, Callable], edges: dict[str, str], cond_edges: dict[str, tuple[Callable, dict]], entry: str):
        self._nodes = nodes
        self._edges = edges
        self._cond_edges = cond_edges
        self._entry = entry

    def invoke(self, state: dict[str, Any]) -> dict[str, Any]:
        current = self._entry
        visited_guard = 0
        while current != END:
            visited_guard += 1
            if visited_guard > 100:
                raise RuntimeError("Graph exceeded max step guard (possible cycle).")
            fn = self._nodes[current]
            result = fn(state)
            if isinstance(result, dict):
                state.update(result)

            if current in self._cond_edges:
                router, mapping = self._cond_edges[current]
                key = router(state)
                current = mapping.get(key, END)
            elif current in self._edges:
                current = self._edges[current]
            else:
                current = END
        return state


class StateGraph:
    def __init__(self, schema: Any = None):
        self._nodes: dict[str, Callable] = {}
        self._edges: dict[str, str] = {}
        self._cond_edges: dict[str, tuple[Callable, dict]] = {}
        self._entry: str | None = None

    def add_node(self, name: str, fn: Callable) -> None:
        self._nodes[name] = fn

    def set_entry_point(self, name: str) -> None:
        self._entry = name

    def add_edge(self, start: str, end: str) -> None:
        self._edges[start] = end

    def add_conditional_edges(self, start: str, router: Callable, mapping: dict[str, str]) -> None:
        self._cond_edges[start] = (router, mapping)

    def compile(self) -> CompiledGraph:
        if self._entry is None:
            raise ValueError("No entry point set")
        return CompiledGraph(self._nodes, self._edges, self._cond_edges, self._entry)
