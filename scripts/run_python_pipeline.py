from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.python_analysis import run_python_analysis


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Python AST preprocessing, VulBridge matching, parameter propagation, and path selection."
    )
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--downstream", required=True)
    parser.add_argument("--selected-count", type=int, default=3)
    args = parser.parse_args()

    try:
        summary = run_python_analysis(
            metadata_path=args.metadata.resolve(),
            case_id=args.case_id,
            downstream=args.downstream,
            output_root=PROJECT_ROOT,
            selected_count=args.selected_count,
        )
    except Exception as exc:
        print(f"ERROR: python pipeline failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
