# ARIA Architecture

## Repository layout

```
aria/
  state.py             Shared IncidentState schema + record_findings() merge helper
  graph.py             LangGraph orchestration: nodes, routing, decide_next()
  _graph_compat.py      Minimal LangGraph-API-compatible fallback (see below)
  cli.py               `aria investigate ...` command-line entrypoint

  ingestion/
    disk.py            Disk image -> normalized suspicious-file/ransom-note/MFT/prefetch data
    memory.py          Memory dump -> normalized process/LSASS-access/malfind/netconn data
    logs.py            Log bundle -> normalized event timeline + per-identity IAM profile
    pcap.py             PCAP -> normalized flow + alert data

  tools/
    autotriage.py        Disk triage; sets malware/ransomware routing signals
    volai.py              Memory forensics; sets credential-theft/beaconing signals
    iam_auditor.py         Identity audit; sets identity-compromise signals
    pcap_analyst.py        Network analysis; confirms/denies C2 signals from VolAI
    detection_engineer.py  Cross-tool correlation + Sigma-style rule drafting

  attck/
    mitre_mapping.py     Local ATT&CK technique/tactic lookup table
    heatmap.py            Navigator layer JSON + standalone HTML heatmap generation

  reports/
    common.py             Shared sorting/formatting helpers
    executive.py           CEO/board report renderer
    technical.py            SOC/analyst report renderer
    legal.py                 Court/regulator evidence report renderer

data/sample_incident/     Synthetic ransomware + credential-theft case, one manifest per artifact kind
examples/output/          Generated report packages land here (gitignored except .gitkeep)
tests/test_investigation.py   Smoke tests: full-evidence run, partial-evidence run, empty run
docs/architecture.mmd     Source for the Mermaid diagram in README.md
.github/workflows/ci.yml  Runs smoke tests + a full demo investigation on every push/PR
```

## Data flow

1. **`cli.py`** builds an `Artifact` list from whatever `--disk/--memory/--logs/--pcap`
   flags were passed, opens a new `IncidentState` (`state.py`), and calls
   `graph.run_investigation(state)`.

2. **`graph.py`** compiles a `StateGraph` with one node per tool
   (`AutoTriage`, `VolAI`, `IAM Auditor`, `AI PCAP Analyst`,
   `AI Detection Engineer`). `AutoTriage` is always the entry point — it's
   the cheapest signal source and every case starts there whether or not a
   disk image was actually provided (if not, it's a no-op that still lets
   the orchestrator move on).

3. After each of the four evidence-gathering nodes, **`decide_next(state)`**
   runs as a LangGraph conditional edge. It looks at:
   - which tools have already completed (`state["completed_tools"]`)
   - which artifacts are actually available (`state["artifacts"]`)
   - which routing signals upstream tools set (`state["signals"]`, e.g.
     `needs_memory_analysis`, `credential_theft`, `needs_pcap_analysis`)

   and returns the name of the next node to run, or routes to
   `AI Detection Engineer` once no evidence-gathering tool is both available
   and incomplete. This is the mechanism that makes ARIA agentic: the same
   code path can produce `AutoTriage -> VolAI -> IAM Auditor -> AI PCAP Analyst`
   for one case and `AutoTriage -> IAM Auditor` for another, based purely on
   what was found, not on argument order.

4. Each tool node calls its module's `run(state) -> list[Finding]`, then
   `state.record_findings()` merges those findings into
   `state["findings"]`, `state["iocs"]`, and `state["attack_techniques"]`
   (a technique-ID -> occurrence-count map used directly by the heatmap).

5. **`AI Detection Engineer`** runs last unconditionally. It doesn't
   re-parse artifacts — it looks at accumulated signals/findings across
   every prior tool, emits cross-domain "attack chain" findings (e.g.
   "the dropper AutoTriage found is the same process VolAI saw dumping
   credentials"), and drafts Sigma-style detection rules into
   `state["detection_rules"]`.

6. Back in `cli.py`, the final state is handed to:
   - `reports.write_all_reports()` → three Markdown reports
   - `attck.heatmap.write_heatmap_artifacts()` → Navigator layer JSON + standalone HTML
   - a full JSON dump of the case state, for programmatic consumption

## Why there's a `_graph_compat.py`

`aria/graph.py` is written against the real `langgraph.graph.StateGraph`
API (`add_node`, `add_conditional_edges`, `set_entry_point`, `compile().invoke(...)`)
and lists `langgraph` as a normal dependency in `requirements.txt` /
`pyproject.toml`. `_graph_compat.py` implements the same handful of methods
as a zero-dependency fallback, purely so this repository can be cloned and
exercised (including in CI environments with restricted network access)
without requiring `pip install langgraph` to succeed first. `graph.py`
imports the real package first and only falls back to the shim on
`ImportError` — production deployments that install `requirements.txt`
normally always get real LangGraph.

## Extending ARIA

- **Add a new tool**: create `aria/tools/your_tool.py` with a `run(state) ->
  list[Finding]` function, register it in `_TOOL_MODULES` in `graph.py`,
  add a case to `decide_next()` for when it should run, and add it to
  `routing_map` / the conditional-edges wiring in `build_graph()`.
- **Add a new report format**: create `aria/reports/your_format.py` with a
  `render(state) -> str` function and wire it into
  `reports/__init__.py::write_all_reports()`.
- **Swap in a real forensic backend**: see the "Production Readiness" table
  in `README.md` — each `aria/ingestion/*.py` module documents its intended
  swap-in point and keeps the same output shape so no downstream code needs
  to change.
