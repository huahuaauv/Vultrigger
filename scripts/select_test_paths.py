from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.reachability.path_ranker import (
    RankedPath,
    extract_test_hints,
    load_json,
    rank_paths,
    select_paths_for_tests,
)


def _human_reasons(rp: RankedPath) -> list[str]:
    out: list[str] = []
    sb = rp.score_breakdown
    st = str((rp.path.get("carrier") or {}).get("status", "")).lower()
    if st == "confirmed":
        out.append("Carrier is confirmed near bridge")
    elif st == "strong_candidate":
        out.append("Carrier is strong_candidate near bridge")
    elif st == "candidate":
        out.append("Carrier is candidate near bridge")
    if sb.get("local_flow_score", 0) >= 18:
        out.append("Local carrier chain reaches HttpClient execute or setURI sink")
    elif sb.get("local_flow_score", 0) >= 10:
        out.append("Partial local carrier chain toward HTTP request construction")
    if sb.get("bridge_score", 0) >= 22:
        out.append("Bridge argument is URI/request-like (constructor or setURI pattern)")
    if sb.get("entry_score", 0) >= 6:
        out.append("Public entry with URI-like parameters")
    if sb.get("testability_score", 0) >= 3:
        out.append("Path is relatively suitable for isolated test generation")
    if not out:
        out.append("Ranked by aggregate carrier/bridge/local-flow/entry/complexity score")
    return out


def main() -> int:
    p = argparse.ArgumentParser(description="Rank parameter paths and emit selected_test_paths.json")
    p.add_argument("--parameter-reachable-paths", type=Path, required=True)
    p.add_argument("--parameter-flow-graph", type=Path, required=True)
    p.add_argument("--metadata", type=Path, required=True)
    p.add_argument("--case-id", required=True)
    p.add_argument("--downstream", required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--selected-count", type=int, default=3)
    args = p.parse_args()

    reachable_doc = load_json(args.parameter_reachable_paths.resolve())
    flow_doc = load_json(args.parameter_flow_graph.resolve())
    metadata = load_json(args.metadata.resolve())

    ranked, _partial_summary = rank_paths(reachable_doc)
    selected = select_paths_for_tests(ranked, max(0, args.selected_count))

    confirmed_n = int(reachable_doc.get("summary", {}).get("parameter_confirmed_reachable_count", 0))
    candidate_n = int(reachable_doc.get("summary", {}).get("parameter_candidate_reachable_count", 0))
    method_only_n = int(reachable_doc.get("summary", {}).get("method_only_reachable_count", 0))
    total_paths = int(reachable_doc.get("summary", {}).get("method_flow_path_count", len(reachable_doc.get("reachable_paths") or [])))

    hints = extract_test_hints(metadata, args.case_id, args.downstream)
    vuln_api = flow_doc.get("vulnerable_api") or {}

    warnings: list[str] = []
    if confirmed_n == 0:
        warnings.append(
            "No parameter_confirmed_reachable path exists; selected paths are candidate paths for dynamic validation."
        )
        warnings.append(
            "当前没有 parameter_confirmed_reachable 路径；selected paths 是基于局部 carrier 链和"
            "方法级可达性的候选路径，后续必须通过动态单元测试验证。"
        )

    ranked_rows: list[dict[str, Any]] = []
    for i, rp in enumerate(ranked, start=1):
        row = rp.to_ranking_row(i)
        ranked_rows.append(row)

    out_dir = args.output_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    ranking_report = {
        "case_id": args.case_id,
        "downstream": args.downstream,
        "ranking_policy": "carrier_bridge_localflow_entry_complexity_testability_v1",
        "paths": ranked_rows,
        "summary": {
            "total_paths": total_paths,
            "ranked_paths": len(ranked),
            "selected_paths": len(selected),
            "method_only_excluded": method_only_n,
        },
    }
    (out_dir / "path_ranking_report.json").write_text(
        json.dumps(ranking_report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    sel_confirmed = sum(1 for x in selected if x.reachability_status == "parameter_confirmed_reachable")
    sel_candidate = sum(1 for x in selected if x.reachability_status == "parameter_candidate_reachable")

    selected_payload: list[dict[str, Any]] = []
    for i, rp in enumerate(selected, start=1):
        base = dict(rp.path)
        bp = base.get("bridge_point") or {}
        selected_payload.append(
            {
                "rank": i,
                "path_id": rp.path_id,
                "score": rp.score,
                "selection_reason": _human_reasons(rp),
                "reachability_status": rp.reachability_status,
                "entry": base.get("entry") or {},
                "bridge_point": bp,
                "carrier": base.get("carrier") or {},
                "method_path": base.get("method_path") or [],
                "parameter_flow": base.get("parameter_flow") or {},
                "test_generation_hints": {
                    **hints,
                    "vulnerable_api": vuln_api,
                    "bridge_argument_summary": rp.bridge_argument,
                    "local_carrier_chain_summary": rp.local_chain_summary or "(no parameter_flow nodes)",
                },
            }
        )

    selected_doc = {
        "case_id": args.case_id,
        "cve_id": reachable_doc.get("cve_id") or args.case_id,
        "downstream": args.downstream,
        "selection_target": "unit_test_generation",
        "selected_count": args.selected_count,
        "actual_selected_count": len(selected),
        "selection_policy": "parameter_candidate_path_selection_v1",
        "selected_paths": selected_payload,
        "summary": {
            "candidate_path_count": candidate_n,
            "method_only_path_count": method_only_n,
            "ranked_path_count": len(ranked),
            "actual_selected_count": len(selected),
            "selected_confirmed_reachable_count": sel_confirmed,
            "selected_candidate_reachable_count": sel_candidate,
        },
        "warnings": warnings,
    }
    (out_dir / "selected_test_paths.json").write_text(
        json.dumps(selected_doc, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"wrote {out_dir / 'path_ranking_report.json'}")
    print(f"wrote {out_dir / 'selected_test_paths.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
