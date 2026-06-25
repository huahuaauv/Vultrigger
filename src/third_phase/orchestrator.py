from __future__ import annotations

import os
import shlex
from pathlib import Path
from typing import Any

from src.third_phase.agents.debugger_agent import DebuggerAgent
from src.third_phase.agents.generator_agent import GeneratorAgent
from src.third_phase.agents.prompt_agent import PromptAgent, get_required_runtime_markers
from src.third_phase.agents.verifier_agent import VerifierAgent
from src.third_phase.api_facts_extractor import build_api_facts
from src.third_phase.context_ranker import rank_context_for_generation
from src.third_phase.context_retriever import ContextRetriever
from src.third_phase.test_plan_builder import build_test_plan
from src.third_phase import executor as execmod
from src.third_phase.io import ensure_dir, read_json, write_json, write_text
from src.third_phase.llm_client import (
    LLMClient,
    OpenAICompatibleClient,
    try_build_optional_llm_clients_from_config_file,
    try_build_optional_llm_clients_from_env,
)
from src.third_phase.models import GenerationResult, TestTask, Verdict


def mvn_tokens_from_downstream(ds: dict[str, Any]) -> list[str]:
    cmd = str((ds.get("build_hint") or {}).get("command") or "").strip()
    if not cmd:
        return ["-DskipTests=true", "-Dspotbugs.skip=true", "-Dcheckstyle.skip=true", "-Dlicense.skip=true", "-Dmaven.javadoc.skip=true", "-Djacoco.skip=true"]
    parts = shlex.split(cmd, posix=os.name != "nt")
    if not parts:
        return []
    head = parts[0].replace("\\", "/").split("/")[-1].lower()
    if head in ("mvn", "mvn.cmd"):
        parts = parts[1:]
    out: list[str] = []
    for p in parts:
        if p == "clean":
            continue
        if p in ("test-compile", "compile", "install", "package", "verify", "test"):
            continue
        out.append(p)
    return out


def _read_generator_system_prompt() -> str:
    p = Path(__file__).resolve().parent / "templates" / "generator_system_prompt.md"
    return p.read_text(encoding="utf-8") if p.is_file() else ""


class ThirdPhaseOrchestrator:
    def __init__(
        self,
        *,
        output_root: Path,
        metadata_path: Path,
        case_id: str,
        downstream: str,
        dry_run: bool = False,
        deterministic_smoke_only: bool = False,
        no_llm: bool = False,
        max_paths: int = 3,
        llm_client: OpenAICompatibleClient | None = None,
        llm_clients: dict[str, LLMClient] | None = None,
        llm_config_path: str | None = None,
    ) -> None:
        self.output_root = output_root.resolve()
        self.metadata_path = metadata_path.resolve()
        self.case_id = case_id
        self.downstream = downstream
        self.dry_run = dry_run
        self.deterministic_smoke_only = deterministic_smoke_only
        self.no_llm = no_llm
        self.max_paths = max_paths
        self.llm_client = llm_client
        self.llm_clients = dict(llm_clients or {})
        self.llm_config_path = llm_config_path
        self._retriever = ContextRetriever()
        self._prompt = PromptAgent()
        self._debugger = DebuggerAgent()
        self._verifier = VerifierAgent()

    def _downstream_dict(self, meta: dict[str, Any]) -> dict[str, Any]:
        case = meta.get(self.case_id) or {}
        for d in case.get("downstreams") or []:
            if isinstance(d, dict) and str(d.get("name")) == self.downstream:
                return d
        raise ValueError(f"downstream {self.downstream} not found")

    def run(self, tasks: list[TestTask], max_rounds_per_path: int) -> dict[str, Any]:
        meta = read_json(self.metadata_path)
        case_meta = meta.get(self.case_id) or {}
        ds = self._downstream_dict(meta)
        mvn_tokens = mvn_tokens_from_downstream(ds)
        compile_args = execmod.build_maven_compile_args(mvn_tokens)
        test_args = execmod.build_maven_test_args(mvn_tokens)

        gen_sys = _read_generator_system_prompt()
        bridge_hint = ""
        if tasks:
            bridge_hint = (
                f"{tasks[0].bridge_point.get('enclosing_type', '')}.{tasks[0].bridge_point.get('enclosing_method', '')}"
            )

        llm_enabled = not self.dry_run and not self.deterministic_smoke_only and not self.no_llm
        active_llm_clients: dict[str, LLMClient] = dict(self.llm_clients or {})
        if self.llm_client is not None and not active_llm_clients:
            active_llm_clients = {
                "prompt": self.llm_client,
                "generator": self.llm_client,
                "debugger": self.llm_client,
                "verifier": self.llm_client,
            }
        if llm_enabled:
            if not active_llm_clients:
                active_llm_clients = try_build_optional_llm_clients_from_config_file(self.llm_config_path) or {}
            if not active_llm_clients:
                active_llm_clients = try_build_optional_llm_clients_from_env() or {}
            missing_roles = [r for r in ("prompt", "generator", "debugger", "verifier") if r not in active_llm_clients]
            if missing_roles:
                raise RuntimeError(
                    "LLM not configured for all third-phase agents: missing "
                    + ", ".join(missing_roles)
                    + ". Fill prompt_model/generator_model/debugger_model/verifier_model in config/llm_config.json, "
                    + "or set OPENAI_API_KEY / DASHSCOPE_API_KEY to share one model across roles, "
                    + "or use --dry-run / --no-llm / --deterministic-smoke-only."
                )

        self._prompt = PromptAgent(active_llm_clients.get("prompt") if llm_enabled else None)
        self._debugger = DebuggerAgent(active_llm_clients.get("debugger") if llm_enabled else None)
        self._verifier = VerifierAgent(active_llm_clients.get("verifier") if llm_enabled else None)
        gen_agent = GeneratorAgent(active_llm_clients.get("generator") if llm_enabled else None)

        selected_n = min(len(tasks), self.max_paths)
        sliced = tasks[:selected_n]
        paths_out: list[dict[str, Any]] = []
        global_success = False
        successful_path_id: str | None = None
        final_stage = "NO_ATTEMPT"
        attempted = 0
        eff_rounds = 1 if self.deterministic_smoke_only else max_rounds_per_path

        for idx, task in enumerate(sliced, start=1):
            trace = self.output_root / f"path_{idx:04d}"
            ensure_dir(trace)
            work = trace / "work"
            ensure_dir(work)
            proj = Path(task.project_root)
            ctx_raw = self._retriever.retrieve(task)
            facts = build_api_facts(proj, task, ctx_raw)
            markers = get_required_runtime_markers(task)
            test_plan = build_test_plan(
                task,
                facts,
                case_meta=case_meta,
                ds_meta=ds,
                verifier_required_markers=markers,
            )
            ranked_ctx, manifest, rank_meta = rank_context_for_generation(
                task, test_plan, ctx_raw, project_root=proj
            )

            task_dict = task.to_dict()
            task_dict["test_plan"] = test_plan
            write_json(trace / "test_task.json", task_dict)
            write_json(trace / "test_plan.json", test_plan)
            write_json(trace / "context_pack.json", ranked_ctx.to_dict())
            write_json(trace / "context_ranked.json", {**ranked_ctx.to_dict(), "ranking_meta": rank_meta})
            write_json(trace / "selected_context_manifest.json", {"snippets": manifest, "ranking_meta": rank_meta})
            write_json(trace / "generation_constraints.json", test_plan.get("code_generation_constraints") or {})
            write_json(trace / "upstream_poc_reference.json", test_plan.get("upstream_poc_reference") or {})
            write_json(trace / "api_facts.json", facts)

            path_final = "UNKNOWN"
            best_evidence: dict[str, Any] = {}
            rounds_used = 0
            prev_board: dict[str, Any] | None = None

            if self.dry_run:
                pp0 = self._prompt.build_prompt_package(task, ranked_ctx, facts, None, test_plan=test_plan)
                write_json(trace / "prompt_package.json", pp0.to_dict())
                write_json(trace / "verifier_package.json", pp0.verifier_package)
                write_text(trace / "prompt_rendered.txt", str(pp0.metadata.get("prompt_rendered") or ""))
                path_final = "DRY_RUN"
                paths_out.append(
                    {
                        "path_id": task.path_id,
                        "rank": task.rank,
                        "rounds": 0,
                        "final_stage": path_final,
                        "best_evidence": {},
                        "trace_dir": str(trace),
                    }
                )
                final_stage = "DRY_RUN"
                continue

            attempted += 1

            execmod.clean_generated_tests(proj)
            smoke_body = execmod.smoke_method_body(task)
            write_text(work / "smoke_body.txt", smoke_body)
            execmod.write_generated_test(proj, smoke_body)
            ok_smoke, smoke_blob = execmod.compile_only_test(proj, compile_args, work)
            write_text(work / "compile_only.log", smoke_blob)
            if not ok_smoke:
                path_final = "PRECHECK_FAILED"
                write_json(
                    trace / "round_01_run_summary.json",
                    {
                        "compile_success": False,
                        "failure_stage": "PRECHECK_FAILED",
                        "compile_excerpt": smoke_blob[-4000:],
                    },
                )
                paths_out.append(
                    {
                        "path_id": task.path_id,
                        "rank": task.rank,
                        "rounds": 0,
                        "final_stage": path_final,
                        "best_evidence": {"compile_success": False},
                        "trace_dir": str(trace),
                    }
                )
                final_stage = path_final
                continue

            for rnd in range(1, eff_rounds + 1):
                rounds_used = rnd
                if global_success:
                    break

                pp = self._prompt.build_prompt_package(task, ranked_ctx, facts, prev_board, test_plan=test_plan)
                write_json(trace / "prompt_package.json", pp.to_dict())
                write_json(trace / "verifier_package.json", pp.verifier_package)
                write_text(trace / "prompt_rendered.txt", str(pp.metadata.get("prompt_rendered") or ""))

                write_json(
                    trace / f"round_{rnd:02d}_prompt.json",
                    {
                        "system_prompt": pp.system_prompt,
                        "user_prompt": pp.user_prompt,
                        "generator_user_prompt": str(pp.metadata.get("generator_prompt_text") or ""),
                        "round": rnd,
                    },
                )

                if self.deterministic_smoke_only:
                    body = smoke_body
                    gr = GenerationResult(
                        success=True,
                        test_file_relpath="src/test/java/auto/gen/pov/ThirdPhasePOVTest.java",
                        test_class_name="ThirdPhasePOVTest",
                        test_method_name="testCVE202013956SelectedPath",
                        method_body=body,
                        method_body_b64="",
                        validated_ok=True,
                        validation_errors=[],
                        raw_model_output="",
                        metadata={"mode": "deterministic_smoke_only"},
                    )
                elif self.no_llm:
                    body = execmod.deterministic_no_llm_body(task)
                    gr = GenerationResult(
                        success=True,
                        test_file_relpath="src/test/java/auto/gen/pov/ThirdPhasePOVTest.java",
                        test_class_name="ThirdPhasePOVTest",
                        test_method_name="testCVE202013956SelectedPath",
                        method_body=body,
                        method_body_b64="",
                        validated_ok=True,
                        validation_errors=[],
                        raw_model_output="",
                        metadata={"mode": "no_llm"},
                    )
                else:
                    gr = gen_agent.generate_test(
                        pp,
                        facts,
                        ranked_ctx,
                        prev_board,
                        generator_system_prompt=gen_sys,
                        task_payload=task.payload,
                        bridge_carrier_hint=bridge_hint,
                    )

                write_json(trace / f"round_{rnd:02d}_raw_model_output.json", {"raw": gr.raw_model_output})
                write_json(trace / f"round_{rnd:02d}_validated_output.json", gr.to_dict())

                if not gr.validated_ok:
                    gen_fail_verdict = Verdict(
                        judgement="fail",
                        confidence="high",
                        reason="PRECHECK_FAILED",
                        key_matched_evidence=[],
                        key_differences=gr.validation_errors,
                        next_action="fix_method_body_constraints",
                        metadata={},
                    )
                    rs_fail = execmod.RunSummary(
                        compile_success=False,
                        run_success=False,
                        bridge_hit=False,
                        payload_observed_at_bridge=False,
                        vulnerability_behavior_observed=False,
                        vuln_api_invoked=False,
                        runtime_logs="",
                        compile_excerpt="",
                        run_excerpt="",
                        markers={},
                        generated_test_path="",
                        failure_stage="GENERATION_INVALID",
                        metadata={"validation_errors": gr.validation_errors},
                    )
                    db = self._debugger.debug(task, pp, gr, rs_fail, gen_fail_verdict, prev_board)
                    write_json(trace / f"round_{rnd:02d}_debug_board.json", db.to_dict())
                    prev_board = db.to_dict()
                    path_final = "GENERATION_INVALID"
                    continue

                rs = execmod.compile_and_run(proj, task, gr.method_body, compile_args, test_args, work, skip_instrumentation=False)
                write_json(trace / f"round_{rnd:02d}_run_summary.json", rs.to_dict())
                write_text(work / "run.log", (rs.runtime_logs or "")[-40000:])

                verdict = self._verifier.judge(
                    rs,
                    pp.verifier_package,
                    smoke_only=self.deterministic_smoke_only,
                )
                write_json(trace / f"round_{rnd:02d}_verdict.json", verdict.to_dict())

                best_evidence = {
                    "compile_success": rs.compile_success,
                    "run_success": rs.run_success,
                    "bridge_hit": rs.bridge_hit,
                    "payload_observed_at_bridge": rs.payload_observed_at_bridge,
                    "vulnerability_behavior_observed": rs.vulnerability_behavior_observed,
                }

                if verdict.judgement == "success" and not self.deterministic_smoke_only:
                    global_success = True
                    successful_path_id = task.path_id
                    final_stage = "SUCCESS"
                    path_final = "SUCCESS"
                    break
                if verdict.judgement == "success" and self.deterministic_smoke_only:
                    path_final = "SMOKE_OK"
                    final_stage = "SMOKE_OK"
                    break

                db = self._debugger.debug(task, pp, gr, rs, verdict, prev_board)
                write_json(trace / f"round_{rnd:02d}_debug_board.json", db.to_dict())
                prev_board = db.to_dict()
                path_final = verdict.reason or rs.failure_stage or "FAIL"

            paths_out.append(
                {
                    "path_id": task.path_id,
                    "rank": task.rank,
                    "rounds": rounds_used,
                    "final_stage": path_final,
                    "best_evidence": best_evidence,
                    "trace_dir": str(trace),
                }
            )

            if global_success:
                break

        if self.dry_run:
            final_stage = "DRY_RUN"
        elif global_success:
            final_stage = "SUCCESS"
        elif paths_out:
            final_stage = str(paths_out[-1].get("final_stage") or "FAIL")

        summary = {
            "case_id": self.case_id,
            "downstream": self.downstream,
            "selected_path_count": len(tasks),
            "attempted_path_count": attempted,
            "success": bool(global_success),
            "successful_path_id": successful_path_id,
            "final_stage": final_stage,
            "paths": paths_out,
        }
        write_json(self.output_root / "third_phase_summary.json", summary)
        return summary
