from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.tools.cmd import run_cmd
from src.tools.codeql_runner import csv_to_json, create_database, decode_bqrs, ensure_dir, run_query
from src.vulbridge_processor.VulBridgeProcessor import VulBridgeProcessor
from src.vulbridge_processor.callgraph_bridge_fallback import (
    merge_callgraph_fallback_into_bridge_doc,
    write_bridge_doc,
)
from src.cal_graph_builder.from_codeql_csv import build_call_graph_from_codeql_edges
from src.cal_graph_builder.method_flow_graph import build_method_flow_graph


QUERY_SPECS = [
    (
        "DirectBridgePoints",
        "DirectBridgePoints.ql",
        "direct_bridge_points.csv",
        "direct_bridge_points.json",
        ["file", "line", "enclosing_type", "enclosing_method", "callee_type", "callee_method", "callee_signature", "argument", "confidence"],
    ),
    (
        "HttpClientIndirectSinks",
        "HttpClientIndirectSinks.ql",
        "indirect_sinks.csv",
        "indirect_sinks.json",
        ["file", "line", "enclosing_type", "enclosing_method", "sink_type", "sink_method", "sink_signature", "argument", "confidence"],
    ),
    (
        "CandidateEntries",
        "CandidateEntries.ql",
        "candidate_entries.csv",
        "candidate_entries.json",
        ["file", "line", "entry_type", "entry_method", "entry_signature", "entry_kind", "parameters"],
    ),
    (
        "CallEdges",
        "CallEdges.ql",
        "call_edges.csv",
        "call_edges.json",
        ["caller_type", "caller_method", "caller_signature", "callee_type", "callee_method", "callee_signature", "file", "line"],
    ),
]


def append_log(log_path: Path, text: str) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as f:
        f.write(text + "\n")


def write_maven_settings(settings_path: Path, local_repo: Path) -> None:
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    local_repo.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(
        (
            "<settings>\n"
            f"  <localRepository>{local_repo.as_posix()}</localRepository>\n"
            "  <mirrors>\n"
            "    <mirror>\n"
            "      <id>force-maven-central</id>\n"
            "      <mirrorOf>*</mirrorOf>\n"
            "      <url>https://repo.maven.apache.org/maven2</url>\n"
            "    </mirror>\n"
            "  </mirrors>\n"
            "</settings>\n"
        ),
        encoding="utf-8",
    )


def write_static_summary(summary_path: Path, obj: dict[str, Any]) -> None:
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def _call_edges_json_nonempty(call_edges_path: Path) -> bool:
    if not call_edges_path.is_file():
        return False
    try:
        data = json.loads(call_edges_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    if isinstance(data, list):
        return len(data) > 0
    if isinstance(data, dict):
        for k in ("rows", "data", "edges", "results"):
            v = data.get(k)
            if isinstance(v, list) and len(v) > 0:
                return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Run minimal CodeQL pipeline for confirmed downstream.")
    parser.add_argument("--metadata", default="dataset/metadata/dataset_match_info.json")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--downstream", required=True)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--codeql-bin", default="codeql")
    parser.add_argument(
        "--run-parameter-queries",
        action="store_true",
        help="After main queries, run parameter-level CodeQL on the existing database (no DB recreate).",
    )
    parser.add_argument(
        "--build-parameter-flow-graph",
        action="store_true",
        help="After method_flow generation, build reverse parameter propagation graph (no top-k / no selected paths).",
    )
    args = parser.parse_args()

    metadata_path = Path(args.metadata).resolve()
    data = json.loads(metadata_path.read_text(encoding="utf-8"))
    if args.case_id not in data:
        raise SystemExit(f"case not found: {args.case_id}")
    case = data[args.case_id]
    downstream = next((d for d in case.get("downstreams", []) if d.get("name") == args.downstream), None)
    if not downstream:
        raise SystemExit(f"downstream not found: {args.downstream}")
    if downstream.get("download_status") not in {"downloaded", "existing_valid", "redownloaded"}:
        raise SystemExit(f"downstream download_status invalid: {downstream.get('download_status')}")

    ds_path = Path(downstream["local_path"]).resolve()
    build_cmd = (downstream.get("build_hint") or {}).get("command", "")
    if not build_cmd:
        raise SystemExit("build_hint.command is required")

    case_id = args.case_id
    downstream_name = args.downstream
    db_path = (Path("outputs/codeql_dbs") / case_id / downstream_name).resolve()
    result_root = (Path("outputs/codeql_results") / case_id / downstream_name).resolve()
    bqrs_root = result_root / "bqrs"
    csv_root = result_root / "csv"
    json_root = result_root / "json"
    bridge_path = (Path("outputs/bridge_points") / case_id / downstream_name / "bridge_points.json").resolve()
    logs_root = (Path("logs/codeql") / case_id / downstream_name).resolve()
    ensure_dir(bqrs_root)
    ensure_dir(csv_root)
    ensure_dir(json_root)
    ensure_dir(logs_root)

    database_log = logs_root / "database_create.log"
    query_log = logs_root / "query_run.log"
    decode_log = logs_root / "bqrs_decode.log"
    parse_log = logs_root / "parse_results.log"
    bridge_log = logs_root / "bridge_points.log"
    static_summary_path = Path("outputs/static_summary.json").resolve()

    if build_cmd.strip().startswith("mvn "):
        settings_path = logs_root / "maven_settings.xml"
        local_repo = Path("cache/m2_repository").resolve()
        write_maven_settings(settings_path, local_repo)
        build_cmd = f'{build_cmd} -s "{settings_path.as_posix()}"'

    db_result = create_database(
        codeql_bin=args.codeql_bin,
        db_path=db_path,
        source_root=ds_path,
        build_command=build_cmd,
        log_path=database_log,
        force=args.force,
    )
    if not db_result.ok:
        write_static_summary(
            static_summary_path,
            {
                "case_id": case_id,
                "downstream": downstream_name,
                "status": "database_create_failed",
                "database_create_log": str(database_log),
            },
        )
        return 1

    qlpack_dir = Path("codeql/qlpacks/vulbridge-java").resolve()
    pack_install = run_cmd([args.codeql_bin, "pack", "install"], cwd=qlpack_dir, timeout_sec=1800, log_path=query_log)
    if not pack_install.ok:
        write_static_summary(
            static_summary_path,
            {
                "case_id": case_id,
                "downstream": downstream_name,
                "status": "query_pack_install_failed",
                "query_run_log": str(query_log),
            },
        )
        return 1

    query_status: dict[str, dict[str, Any]] = {}
    any_query_failed = False
    for query_name, query_file_name, csv_name, json_name, headers in QUERY_SPECS:
        ql = (Path("codeql/qlpacks/vulbridge-java/queries") / query_file_name).resolve()
        bqrs = bqrs_root / f"{query_name}.bqrs"
        csv_path = csv_root / csv_name
        json_path = json_root / json_name

        qres = run_query(args.codeql_bin, ql, db_path, bqrs, query_log)
        if not qres.ok:
            any_query_failed = True
            query_status[query_name] = {"ok": False, "count": 0, "error": qres.stderr}
            append_log(query_log, f"[FAIL] {query_name}: {qres.stderr}")
            continue

        dres = decode_bqrs(args.codeql_bin, bqrs, csv_path, decode_log)
        if not dres.ok:
            any_query_failed = True
            query_status[query_name] = {"ok": False, "count": 0, "error": dres.stderr}
            append_log(decode_log, f"[FAIL] {query_name}: {dres.stderr}")
            continue

        count = csv_to_json(csv_path, json_path, headers)
        query_status[query_name] = {"ok": True, "count": count}
        append_log(parse_log, f"[OK] {query_name}: {count}")

    direct_json = json_root / "direct_bridge_points.json"
    indirect_json = json_root / "indirect_sinks.json"
    bridge_processor = VulBridgeProcessor(metadata_path=metadata_path)
    bridge_data = bridge_processor.generate_bridge_points(
        case_id=case_id,
        downstream_name=downstream_name,
        direct_json_path=direct_json,
        indirect_json_path=indirect_json,
        codeql_db_path=db_path,
        output_path=bridge_path,
    )
    append_log(bridge_log, f"bridge_points generated: {bridge_path}")

    call_json = json_root / "call_edges.json"
    call_graph_info: dict[str, Any] = {
        "status": "skipped_no_call_edges",
        "node_count": 0,
        "edge_count": 0,
        "path": str((Path("outputs/call_graphs") / case_id / downstream_name).resolve()),
    }
    method_flow_info: dict[str, Any] = {
        "status": "skipped_no_call_edges",
        "path_count": 0,
        "reachable_bridge_point_count": 0,
        "path": str((Path("outputs/method_flows") / case_id / downstream_name).resolve()),
    }

    if _call_edges_json_nonempty(call_json):
        cg_dir = (Path("outputs/call_graphs") / case_id / downstream_name).resolve()
        mf_dir = (Path("outputs/method_flows") / case_id / downstream_name).resolve()
        try:
            csum = build_call_graph_from_codeql_edges(
                call_edges_json=call_json,
                output_dir=cg_dir,
                case_id=case_id,
                downstream_name=downstream_name,
            )
            inner = csum.get("summary") or {}
            call_graph_info = {
                "status": "success",
                "node_count": inner.get("node_count", 0),
                "edge_count": inner.get("edge_count", 0),
                "path": str(cg_dir),
            }
            cgraph_file = cg_dir / "full_callgraph.json"
            if int((bridge_data.get("summary") or {}).get("total_bridge_points", 0) or 0) == 0:
                merged = merge_callgraph_fallback_into_bridge_doc(
                    bridge_data,
                    cgraph_file,
                    case=case,
                    downstream=downstream,
                )
                if int((merged.get("summary") or {}).get("total_bridge_points", 0) or 0) > int(
                    (bridge_data.get("summary") or {}).get("total_bridge_points", 0) or 0
                ):
                    bridge_data = merged
                    write_bridge_doc(bridge_path, bridge_data)
                    append_log(
                        bridge_log,
                        "bridge_points augmented from call graph + metadata bridge hints "
                        f"(total={merged['summary'].get('total_bridge_points')})",
                    )
            cands = json_root / "candidate_entries.json"
            msum = build_method_flow_graph(
                call_graph_json=cgraph_file,
                candidate_entries_json=cands,
                bridge_points_json=bridge_path,
                output_dir=mf_dir,
                max_depth=30,
                max_paths_per_bridge=20,
            )
            ms = msum.get("summary") or {}
            mf_status: str
            if not ms.get("candidate_entries_available"):
                mf_status = "skipped_no_candidate_entries"
            elif msum.get("status") == "success" or msum.get("path_count", 0) > 0:
                mf_status = "success"
            else:
                mf_status = "no_paths_found"
            method_flow_info = {
                "status": mf_status,
                "path_count": msum.get("path_count", ms.get("path_count", 0)),
                "reachable_bridge_point_count": msum.get(
                    "reachable_bridge_point_count", ms.get("reachable_bridge_point_count", 0)
                ),
                "path": str(mf_dir),
            }
            append_log(parse_log, f"[OK] call_graph: nodes={call_graph_info['node_count']} edges={call_graph_info['edge_count']}")
            append_log(
                parse_log,
                f"[OK] method_flow: status={method_flow_info['status']} paths={method_flow_info['path_count']}",
            )
        except Exception as e:
            append_log(parse_log, f"[FAIL] call_graph / method_flow: {e!r}")
            call_graph_info = {
                "status": "failed",
                "error": str(e),
                "node_count": 0,
                "edge_count": 0,
                "path": str(cg_dir),
            }
            method_flow_info = {
                "status": "failed",
                "error": str(e),
                "path_count": 0,
                "reachable_bridge_point_count": 0,
                "path": str(mf_dir),
            }

    parameter_query_summary: dict[str, Any] | None = None
    parameter_flow_build_summary: dict[str, Any] | None = None

    if args.run_parameter_queries:
        pq_cmd = [
            sys.executable,
            str(PROJECT_ROOT / "scripts" / "run_parameter_codeql_queries.py"),
            "--metadata",
            str(metadata_path),
            "--case-id",
            case_id,
            "--downstream",
            downstream_name,
            "--database",
            str(db_path),
            "--codeql-bin",
            args.codeql_bin,
        ]
        subprocess.run(pq_cmd, cwd=str(PROJECT_ROOT), check=False)
        pq_json = json_root / "parameter_query_summary.json"
        if pq_json.is_file():
            parameter_query_summary = json.loads(pq_json.read_text(encoding="utf-8"))

    if args.build_parameter_flow_graph:
        mf_json = (Path("outputs/method_flows") / case_id / downstream_name / "method_flow_paths.json").resolve()
        param_flow_root = (Path("outputs/parameter_flows") / case_id / downstream_name).resolve()
        bf_cmd = [
            sys.executable,
            str(PROJECT_ROOT / "scripts" / "build_parameter_flow_graph.py"),
            "--metadata",
            str(metadata_path),
            "--case-id",
            case_id,
            "--downstream",
            downstream_name,
            "--method-flow",
            str(mf_json),
            "--bridge-points",
            str(bridge_path),
            "--codeql-json-dir",
            str(json_root),
            "--output-dir",
            str(param_flow_root),
        ]
        subprocess.run(bf_cmd, cwd=str(PROJECT_ROOT), check=False)
        summ = (Path("outputs/reachability") / case_id / downstream_name / "parameter_reachability_summary.json").resolve()
        if summ.is_file():
            sdoc = json.loads(summ.read_text(encoding="utf-8"))
            res = sdoc.get("results") or {}
            parameter_flow_build_summary = {
                "parameter_flow_graph": str((param_flow_root / "parameter_flow_graph.json").resolve()),
                "parameter_reachable_paths": str(
                    (Path("outputs/reachability") / case_id / downstream_name / "parameter_reachable_paths.json").resolve()
                ),
                "parameter_reachability_summary": str(summ),
                "parameter_graph_node_count": res.get("parameter_graph_node_count"),
                "parameter_graph_edge_count": res.get("parameter_graph_edge_count"),
            }

    write_static_summary(
        static_summary_path,
        {
            "case_id": case_id,
            "downstream": downstream_name,
            "status": "partial_failed" if any_query_failed else "ok",
            "database_create": "ok",
            "query_status": query_status,
            "bridge_points": str(bridge_path),
            "direct_bridge_points": bridge_data["summary"]["direct_bridge_points"],
            "indirect_bridge_points": bridge_data["summary"]["indirect_bridge_points"],
            "call_graph": call_graph_info,
            "method_flow": method_flow_info,
            "parameter_query_summary": parameter_query_summary,
            "parameter_flow_build": parameter_flow_build_summary,
        },
    )
    return 0 if not any_query_failed else 2


if __name__ == "__main__":
    raise SystemExit(main())
