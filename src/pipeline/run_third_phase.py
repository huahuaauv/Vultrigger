from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.third_phase.io import ensure_dir
from src.third_phase.orchestrator import ThirdPhaseOrchestrator
from src.third_phase.task_adapter import load_selected_test_tasks
from src.third_phase.toolchain_env import prepend_project_toolchain


def main() -> int:
    prepend_project_toolchain(PROJECT_ROOT)
    p = argparse.ArgumentParser(description="Third phase v2: multi-agent test generation + deterministic verification")
    p.add_argument("--metadata", type=Path, default=Path("dataset/metadata/dataset_match_info.json"))
    p.add_argument("--case-id", required=True)
    p.add_argument("--downstream", required=True)
    p.add_argument("--selected-test-paths", type=Path, required=True)
    p.add_argument("--parameter-flow-graph", type=Path, required=True)
    p.add_argument("--parameter-reachable-paths", type=Path, required=True)
    p.add_argument("--output-root", type=Path, default=None, help="default outputs/third_phase/<case>/<downstream>")
    p.add_argument("--max-rounds-per-path", type=int, default=3)
    p.add_argument("--max-paths", type=int, default=3)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--deterministic-smoke-only", action="store_true")
    p.add_argument("--no-llm", action="store_true")
    p.add_argument(
        "--llm-config",
        type=Path,
        default=None,
        help="OpenAI-compatible LLM JSON (default: config/llm_config.json or LLM_CONFIG env). See config/llm_config.example.json",
    )
    args = p.parse_args()

    meta_path = args.metadata.resolve()
    out_root = (
        args.output_root.resolve()
        if args.output_root
        else (PROJECT_ROOT / "outputs" / "third_phase" / args.case_id / args.downstream).resolve()
    )
    ensure_dir(out_root)

    tasks = load_selected_test_tasks(
        meta_path,
        args.selected_test_paths.resolve(),
        parameter_flow_graph_path=args.parameter_flow_graph.resolve(),
        parameter_reachable_paths_path=args.parameter_reachable_paths.resolve(),
    )

    llm_cfg = str(args.llm_config.resolve()) if args.llm_config else None
    orch = ThirdPhaseOrchestrator(
        output_root=out_root,
        metadata_path=meta_path,
        case_id=args.case_id,
        downstream=args.downstream,
        dry_run=args.dry_run,
        deterministic_smoke_only=args.deterministic_smoke_only,
        no_llm=args.no_llm,
        max_paths=args.max_paths,
        llm_client=None,
        llm_config_path=llm_cfg,
    )
    summary = orch.run(tasks, max_rounds_per_path=args.max_rounds_per_path)
    print(
        "final_stage=",
        summary.get("final_stage"),
        "success=",
        summary.get("success"),
        "summary=",
        str(out_root / "third_phase_summary.json"),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
