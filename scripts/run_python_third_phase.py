from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _pytest_scaffold(row: dict[str, Any], payload: str) -> str:
    entry = row.get("entry") or {}
    bridge = row.get("bridge_point") or {}
    carrier = row.get("carrier") or {}
    return f'''"""
Auto-generated VulTrigger Python scaffold.
This file is intentionally conservative: it records the selected downstream
entry, VulBridge candidate, carrier, and payload so a Python-specific LLM or
manual validation step can complete project-specific object construction.
"""


def test_vultrigger_selected_path_documentation():
    payload = {payload!r}
    selected_entry = {entry.get("signature", "")!r}
    selected_bridge = {bridge.get("callee_signature", "")!r}
    selected_carrier = {carrier.get("name", "")!r}
    assert payload is not None
    assert selected_entry
    assert selected_bridge
    # Runtime triggerability still requires executing the real downstream entry
    # and observing the bridge/probe behavior in the target project.
'''


def main() -> int:
    p = argparse.ArgumentParser(description="Python third phase scaffold/report for selected AST paths.")
    p.add_argument("--metadata", type=Path, required=True)
    p.add_argument("--case-id", required=True)
    p.add_argument("--downstream", required=True)
    p.add_argument("--selected-test-paths", type=Path, required=True)
    p.add_argument("--parameter-flow-graph", type=Path, required=True)
    p.add_argument("--parameter-reachable-paths", type=Path, required=True)
    p.add_argument("--output-root", type=Path, default=None)
    p.add_argument("--max-paths", type=int, default=3)
    p.add_argument("--max-rounds-per-path", type=int, default=3)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--no-llm", action="store_true")
    p.add_argument("--deterministic-smoke-only", action="store_true")
    args = p.parse_args()

    selected_doc = _read_json(args.selected_test_paths.resolve())
    selected = [x for x in selected_doc.get("selected_paths") or [] if isinstance(x, dict)]
    out_root = (
        args.output_root.resolve()
        if args.output_root
        else (PROJECT_ROOT / "outputs" / "third_phase" / args.case_id / args.downstream).resolve()
    )
    out_root.mkdir(parents=True, exist_ok=True)

    meta = _read_json(args.metadata.resolve())
    case_doc = meta.get(args.case_id) or {}
    ds_doc = next((d for d in case_doc.get("downstreams") or [] if isinstance(d, dict) and d.get("name") == args.downstream), {})
    payloads = (case_doc.get("poc") or {}).get("payloads") or []
    payload = str(ds_doc.get("poc_payload") or (payloads[0] if payloads else "") or "")

    paths_out: list[dict[str, Any]] = []
    for idx, row in enumerate(selected[: max(0, args.max_paths)], start=1):
        trace = out_root / f"path_{idx:04d}"
        work = trace / "work"
        work.mkdir(parents=True, exist_ok=True)
        scaffold = _pytest_scaffold(row, payload)
        (work / "test_vultrigger_python_scaffold.py").write_text(scaffold, encoding="utf-8")
        (trace / "test_task.json").write_text(json.dumps(row, ensure_ascii=False, indent=2), encoding="utf-8")
        (trace / "python_validation_report.json").write_text(
            json.dumps(
                {
                    "language": "python",
                    "status": "scaffold_ready",
                    "runtime_executed": False,
                    "reason": "Python AST branch produced a constrained path and pytest scaffold; project-specific runtime execution is not claimed as success.",
                    "required_runtime_evidence": [
                        "downstream entry executed",
                        "VulBridge/probe hit",
                        "payload observed at bridge",
                        "expected or differential vulnerable behavior observed",
                    ],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        paths_out.append(
            {
                "path_id": row.get("path_id"),
                "rank": row.get("rank"),
                "rounds": 0,
                "final_stage": "PYTHON_SCAFFOLD_READY",
                "best_evidence": {
                    "compile_success": False,
                    "run_success": False,
                    "bridge_hit": False,
                    "payload_observed_at_bridge": False,
                    "vulnerability_behavior_observed": False,
                },
                "trace_dir": str(trace),
            }
        )

    summary = {
        "case_id": args.case_id,
        "downstream": args.downstream,
        "language": "python",
        "selected_path_count": len(selected),
        "attempted_path_count": len(paths_out),
        "success": False,
        "successful_path_id": None,
        "final_stage": "PYTHON_SCAFFOLD_READY" if paths_out else "NO_SELECTED_PATHS",
        "paths": paths_out,
    }
    (out_root / "third_phase_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print("final_stage=", summary["final_stage"], "success=", summary["success"], "summary=", out_root / "third_phase_summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
