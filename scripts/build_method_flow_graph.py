from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.cal_graph_builder.method_flow_graph import build_method_flow_graph


def main() -> int:
    p = argparse.ArgumentParser(description="Build entry -> bridge method flow from call graph + metadata")
    p.add_argument("--call-graph", type=Path, required=True, help="full_callgraph.json")
    p.add_argument("--candidate-entries", type=Path, required=True)
    p.add_argument("--bridge-points", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--max-depth", type=int, default=30)
    p.add_argument("--max-paths-per-bridge", type=int, default=20)
    args = p.parse_args()
    out = build_method_flow_graph(
        call_graph_json=args.call_graph,
        candidate_entries_json=args.candidate_entries,
        bridge_points_json=args.bridge_points,
        output_dir=args.output_dir,
        max_depth=args.max_depth,
        max_paths_per_bridge=args.max_paths_per_bridge,
    )
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
