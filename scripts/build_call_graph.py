from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.cal_graph_builder.from_codeql_csv import build_call_graph_from_codeql_edges


def main() -> int:
    p = argparse.ArgumentParser(description="Build method call graph from CodeQL call_edges.json")
    p.add_argument("--call-edges", type=Path, required=True, help="Path to call_edges.json (or .csv)")
    p.add_argument("--case-id", required=True)
    p.add_argument("--downstream", required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    args = p.parse_args()
    out = build_call_graph_from_codeql_edges(
        call_edges_json=args.call_edges,
        output_dir=args.output_dir,
        case_id=args.case_id,
        downstream_name=args.downstream,
    )
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
