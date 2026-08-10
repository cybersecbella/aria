#!/usr/bin/env python3
"""ARIA command-line entrypoint.

    aria investigate \
        --case-name "Northshore Clinic Ransomware" \
        --disk data/sample_incident/disk_manifest.json \
        --memory data/sample_incident/memory_manifest.json \
        --logs data/sample_incident/log_manifest.json \
        --pcap data/sample_incident/pcap_manifest.json \
        --analyst "J. Rivera" \
        --out examples/output

One command: ingest whatever artifacts you have, let the LangGraph
orchestrator decide which tools to run, and emit the full report package --
executive brief, technical findings, legal evidence report, and an ATT&CK
heatmap -- into the output directory.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import uuid
from pathlib import Path

from aria.attck.heatmap import write_heatmap_artifacts
from aria.graph import run_investigation
from aria.reports import write_all_reports
from aria.state import new_state


def _artifact(kind: str, path: str | None) -> dict | None:
    if not path:
        return None
    p = Path(path)
    return {
        "kind": kind,
        "path": str(p),
        "sha256": "unverified-in-demo-mode",
        "collected_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "description": f"{kind.title()} artifact manifest provided at CLI invocation.",
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aria", description="ARIA -- AI-orchestrated incident response agent.")
    sub = parser.add_subparsers(dest="command", required=True)

    inv = sub.add_parser("investigate", help="Run a full investigation across provided evidence.")
    inv.add_argument("--case-name", required=True, help="Human-readable case name.")
    inv.add_argument("--analyst", default="Unassigned", help="Analyst of record for the case.")
    inv.add_argument("--disk", help="Path to disk evidence manifest.")
    inv.add_argument("--memory", help="Path to memory evidence manifest.")
    inv.add_argument("--logs", help="Path to log evidence manifest.")
    inv.add_argument("--pcap", help="Path to pcap evidence manifest.")
    inv.add_argument("--out", default="examples/output", help="Output directory for reports and heatmap.")
    inv.add_argument("--case-id", default=None, help="Override the generated case ID.")

    return parser


def cmd_investigate(args: argparse.Namespace) -> int:
    artifacts = [
        a
        for a in (
            _artifact("disk", args.disk),
            _artifact("memory", args.memory),
            _artifact("logs", args.logs),
            _artifact("pcap", args.pcap),
        )
        if a is not None
    ]

    if not artifacts:
        print("error: at least one of --disk / --memory / --logs / --pcap is required", file=sys.stderr)
        return 2

    case_id = args.case_id or f"ARIA-{dt.datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    state = new_state(
        case_id=case_id,
        case_name=args.case_name,
        analyst=args.analyst,
        artifacts=artifacts,
        started_at=dt.datetime.now(dt.timezone.utc).isoformat(),
    )

    print(f"[ARIA] Opening case {case_id} -- {args.case_name}")
    print(f"[ARIA] Artifacts: {', '.join(a['kind'] for a in artifacts)}")
    print("[ARIA] Running LangGraph orchestration (agent decides tool order dynamically)...")

    result = run_investigation(state)

    print(f"[ARIA] Investigation complete. {len(result.get('findings', []))} findings across "
          f"{len(result.get('tool_runs', []))} tool run(s).")
    for run in result.get("tool_runs", []):
        print(f"    -> {run['tool']}: {run['finding_count']} finding(s) -- {run.get('reason')}")

    out_dir = Path(args.out) / case_id
    out_dir.mkdir(parents=True, exist_ok=True)

    report_paths = write_all_reports(result, str(out_dir))
    layer_path, html_path = write_heatmap_artifacts(result, str(out_dir))
    result["report_paths"] = report_paths
    result["heatmap_layer_path"] = layer_path
    result["heatmap_html_path"] = html_path

    # Persist the full state as JSON for programmatic consumption / audit.
    state_dump = {**result}
    state_dump["iocs"] = sorted(state_dump.get("iocs", set()))
    state_dump["completed_tools"] = sorted(state_dump.get("completed_tools", set()))
    (out_dir / "case_state.json").write_text(json.dumps(state_dump, indent=2, default=str), encoding="utf-8")

    print(f"[ARIA] Reports written to {out_dir}/")
    for name, path in report_paths.items():
        print(f"    - {name}: {path}")
    print(f"    - attck heatmap (html): {html_path}")
    print(f"    - attck navigator layer (json): {layer_path}")
    print(f"    - full case state: {out_dir / 'case_state.json'}")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    if args.command == "investigate":
        return cmd_investigate(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
