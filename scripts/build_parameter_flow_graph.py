from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.reachability.parameter_graph_builder import build_parameter_flow_outputs


def main() -> int:
    p = argparse.ArgumentParser(description="Build reverse parameter propagation graph from CodeQL + method_flow.")
    p.add_argument("--metadata", type=Path, default=Path("dataset/metadata/dataset_match_info.json"))
    p.add_argument("--case-id", required=True)
    p.add_argument("--downstream", required=True)
    p.add_argument("--method-flow", type=Path, required=True)
    p.add_argument("--bridge-points", type=Path, required=True)
    p.add_argument("--codeql-json-dir", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True, help="parameter_flow_graph.json directory")
    args = p.parse_args()

    reach_dir = (
        Path("outputs/reachability") / args.case_id / args.downstream
    ).resolve()
    log_path = (Path("logs/reachability") / args.case_id / args.downstream / "parameter_flow_graph.log").resolve()

    build_parameter_flow_outputs(
        metadata_path=args.metadata.resolve(),
        case_id=args.case_id,
        downstream=args.downstream,
        method_flow_path=args.method_flow.resolve(),
        bridge_points_path=args.bridge_points.resolve(),
        codeql_json_dir=args.codeql_json_dir.resolve(),
        parameter_flow_output_dir=args.output_dir.resolve(),
        reachability_output_dir=reach_dir,
        log_path=log_path,
    )
    print(f"wrote {args.output_dir / 'parameter_flow_graph.json'}")
    print(f"wrote {reach_dir / 'parameter_reachable_paths.json'}")
    print(f"wrote {reach_dir / 'parameter_reachability_summary.json'}")
    print(f"log {log_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
