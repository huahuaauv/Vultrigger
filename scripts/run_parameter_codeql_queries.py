from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.tools.cmd import run_cmd
from src.tools.codeql_runner import csv_to_json, decode_bqrs, ensure_dir, run_query

PARAMETER_QUERY_SPECS: list[tuple[str, str, str, str, list[str]]] = [
    (
        "BridgeArgumentDetails",
        "BridgeArgumentDetails.ql",
        "bridge_argument_details.csv",
        "bridge_argument_details.json",
        [
            "file",
            "line",
            "enclosing_type",
            "enclosing_method",
            "enclosing_signature",
            "bridge_kind",
            "sink_type",
            "sink_method",
            "sink_signature",
            "receiver_text",
            "receiver_type",
            "argument_index",
            "argument_text",
            "argument_type",
            "argument_role",
            "confidence",
        ],
    ),
    (
        "CallSiteArgumentMapping",
        "CallSiteArgumentMapping.ql",
        "callsite_argument_mapping.csv",
        "callsite_argument_mapping.json",
        [
            "file",
            "line",
            "caller_type",
            "caller_method",
            "caller_signature",
            "callee_type",
            "callee_method",
            "callee_signature",
            "argument_index",
            "actual_argument_text",
            "actual_argument_type",
            "formal_parameter_name",
            "formal_parameter_type",
            "receiver_text",
            "receiver_type",
            "call_text",
        ],
    ),
    (
        "LocalCarrierFlow",
        "LocalCarrierFlow.ql",
        "local_carrier_flow.csv",
        "local_carrier_flow.json",
        [
            "file",
            "line",
            "enclosing_type",
            "enclosing_method",
            "enclosing_signature",
            "source_expr",
            "source_type",
            "target_expr",
            "target_type",
            "flow_kind",
            "evidence",
        ],
    ),
    (
        "UriAndRequestConstruction",
        "UriAndRequestConstruction.ql",
        "uri_and_request_construction.csv",
        "uri_and_request_construction.json",
        [
            "file",
            "line",
            "enclosing_type",
            "enclosing_method",
            "enclosing_signature",
            "construction_kind",
            "constructed_expr",
            "constructed_type",
            "variable_name",
            "uri_argument_text",
            "uri_argument_type",
            "source_expression",
            "source_type",
        ],
    ),
]


def append_log(log_path: Path, text: str) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as f:
        f.write(text + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run parameter-level CodeQL queries on an existing database.")
    parser.add_argument("--metadata", default="dataset/metadata/dataset_match_info.json")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--downstream", required=True)
    parser.add_argument("--database", type=Path, required=True, help="Existing CodeQL database path")
    parser.add_argument("--codeql-bin", default="codeql", dest="codeql_bin")
    args = parser.parse_args()

    db_path: Path = args.database.resolve()
    if not (db_path / "codeql-database.yml").is_file():
        print(f"ERROR: not a CodeQL database: {db_path}", file=sys.stderr)
        return 1

    case_id = args.case_id
    downstream = args.downstream
    result_root = (Path("outputs/codeql_results") / case_id / downstream).resolve()
    bqrs_root = result_root / "bqrs"
    csv_root = result_root / "csv"
    json_root = result_root / "json"
    logs_root = (Path("logs/codeql") / case_id / downstream).resolve()
    for d in (bqrs_root, csv_root, json_root, logs_root):
        ensure_dir(d)

    log_path = logs_root / "parameter_queries.log"
    query_log = logs_root / "parameter_query_run.log"
    decode_log = logs_root / "parameter_bqrs_decode.log"

    append_log(log_path, f"database={db_path}")
    append_log(log_path, f"result_root={result_root}")

    qlpack_dir = Path("codeql/qlpacks/vulbridge-java").resolve()
    pack_install = run_cmd([args.codeql_bin, "pack", "install"], cwd=qlpack_dir, timeout_sec=1800, log_path=query_log)
    if not pack_install.ok:
        append_log(log_path, f"[FAIL] pack install: {pack_install.stderr}")
        print(pack_install.stderr, file=sys.stderr)
        return 1

    query_status: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []

    for query_name, ql_name, csv_name, json_name, headers in PARAMETER_QUERY_SPECS:
        ql = (qlpack_dir / "queries" / ql_name).resolve()
        bqrs = bqrs_root / f"{query_name}.bqrs"
        csv_path = csv_root / csv_name
        json_path = json_root / json_name

        qres = run_query(args.codeql_bin, ql, db_path, bqrs, query_log)
        if not qres.ok:
            query_status[query_name] = {"status": "failed", "count": 0, "error": qres.stderr}
            append_log(log_path, f"[FAIL] {query_name}: {qres.stderr}")
            continue

        dres = decode_bqrs(args.codeql_bin, bqrs, csv_path, decode_log)
        if not dres.ok:
            query_status[query_name] = {"status": "decode_failed", "count": 0, "error": dres.stderr}
            append_log(log_path, f"[FAIL] decode {query_name}: {dres.stderr}")
            continue

        count = csv_to_json(csv_path, json_path, headers)
        query_status[query_name] = {"status": "success", "count": count}
        append_log(log_path, f"[OK] {query_name}: count={count}")

    summary_path = json_root / "parameter_query_summary.json"
    summary_obj = {
        "case_id": case_id,
        "downstream": downstream,
        "queries": query_status,
        "warnings": warnings,
    }
    summary_path.write_text(json.dumps(summary_obj, ensure_ascii=False, indent=2), encoding="utf-8")
    append_log(log_path, f"wrote {summary_path}")
    print(json.dumps(summary_obj, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
