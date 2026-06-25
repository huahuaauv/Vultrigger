from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.third_phase.agents.utils import json_only_guard
from src.third_phase.llm_client import LLMClient
from src.third_phase.models import DebugBoard, GenerationResult, PromptPackage, RunSummary, TestTask, Verdict


def _load_md(name: str) -> str:
    p = Path(__file__).resolve().parents[1] / "templates" / name
    return p.read_text(encoding="utf-8") if p.is_file() else ""


def _string_list(value: Any, fallback: list[str], limit: int) -> list[str]:
    if isinstance(value, list):
        out = [str(x).strip() for x in value if str(x).strip()]
        return out[:limit] if out else fallback[:limit]
    if isinstance(value, str) and value.strip():
        return [value.strip()][:limit]
    return fallback[:limit]

def _plan_hint(pp: PromptPackage) -> dict[str, Any]:
    tp = (pp.metadata or {}).get("test_plan") or getattr(pp, "test_plan", None) or {}
    return tp if isinstance(tp, dict) else {}


class DebuggerAgent:
    """LLM debugger with heuristic fallback."""

    def __init__(self, llm: LLMClient | None = None) -> None:
        self.llm = llm

    def _heuristic_debug(
        self,
        task: TestTask,
        prompt_package: PromptPackage,
        generation: GenerationResult,
        run_summary: RunSummary,
        verdict: Verdict,
        previous_debug_board: dict[str, Any] | None,
    ) -> DebugBoard:
        stage = (verdict.reason or run_summary.failure_stage or "").upper()
        prev = previous_debug_board or {}
        plan = _plan_hint(prompt_package)
        entry_sig = str(plan.get("entry_invocation_plan", {}).get("target_method") or task.entry.get("signature") or "")
        inj = plan.get("payload_injection_plan") or {}
        mock_notes = plan.get("mocking_plan") or {}

        if stage == "COMPILE_FAILED" or run_summary.failure_stage == "COMPILE_FAILED":
            return DebugBoard(
                status="COMPILE_FAILED",
                root_cause_top3=[
                    "Generated method body incompatible with project classpath or imports available in the ThirdPhasePOVTest template.",
                    "Missing type / wrong constructor arity for Snowflake or HttpClient classes.",
                    "Method-body-only mode: no new imports -use fully qualified class names for anything not in the template imports.",
                ],
                action_items=[
                    f"Re-check api_facts for entry/bridge class constructors; align with entry `{entry_sig}`.",
                    "Use fully qualified names (e.g. org.mockito.Mockito, java.util.concurrent.atomic.AtomicReference) when Mockito/utility types are not imported.",
                    "If static mocking failed, verify mockito-inline is not assumed unless present in POM.",
                    "Keep changes inside the method body; do not add package/import/class.",
                ],
                evidence=[run_summary.compile_excerpt[-2000:]],
                do_not_repeat=list(prev.get("do_not_repeat", [])) + generation.validation_errors[:5],
                metadata={"round_hint": "compile", "path_id": task.path_id, "test_plan_profile": plan.get("path_profile")},
            )

        if stage == "PRECHECK_FAILED":
            return DebugBoard(
                status="PRECHECK_FAILED",
                root_cause_top3=[
                    "Minimal oracle smoke test failed to compile -Maven project or JDK setup issue.",
                    "Downstream pom excludes tests or requires extra -D flags.",
                ],
                action_items=["Inspect compile_only.log under work/.", "Align Maven token list with dataset build_hint."],
                evidence=[run_summary.compile_excerpt[-2000:]],
                do_not_repeat=[],
                metadata={"path_id": task.path_id},
            )

        if stage == "RUN_FAILED" or run_summary.failure_stage == "RUN_FAILED":
            return DebugBoard(
                status="RUN_FAILED",
                root_cause_top3=[
                    "Runtime exception inside generated test or Snowflake entry path.",
                    "Test assumptions require unavailable mocks/resources -null CloseableHttpResponse or missing stubbed methods.",
                ],
                action_items=[
                    "Add fakes for HttpResponse / StatusLine / Entity if returning a mock CloseableHttpClient.",
                    str(mock_notes.get("network_boundary") or "Intercept network at HttpClient.execute with a fake client."),
                    "Narrow the scenario to the smallest constructor graph suggested in test_plan.entry_invocation_plan.",
                ],
                evidence=[run_summary.run_excerpt[-2500:]],
                do_not_repeat=[],
                metadata={"path_id": task.path_id},
            )

        if stage == "CHAIN_NOT_HIT" or verdict.reason == "CHAIN_NOT_HIT":
            return DebugBoard(
                status="CHAIN_NOT_HIT",
                root_cause_top3=[
                    "Execution did not reach instrumented bridge line for this selected path.",
                    "Wrong entry chosen vs selected_path entry, or payload never reached RestRequest.execute / HttpClient.execute.",
                    "Mocks may have bypassed the real downstream call graph.",
                ],
                action_items=[
                    f"Call the selected entry `{entry_sig}` (or its documented callee chain) before auxiliary oracle code.",
                    f"Drive toward bridge `{task.bridge_point.get('signature')}` at {task.bridge_point.get('file')}:{task.bridge_point.get('line')}",
                    f"Use carrier / injection plan: {inj.get('how_to_inject', '')}",
                ],
                evidence=[(prompt_package.metadata or {}).get("prompt_rendered", prompt_package.user_prompt)[:2000]],
                do_not_repeat=[],
                metadata={"path_id": task.path_id},
            )

        if stage == "PAYLOAD_NOT_OBSERVED" or verdict.reason == "PAYLOAD_NOT_OBSERVED":
            return DebugBoard(
                status="PAYLOAD_NOT_OBSERVED",
                root_cause_top3=[
                    "Bridge line executed but URI at bridge did not contain malformed payload substring.",
                    "Different URI instance passed to setURI/execute than constructed from payload.",
                ],
                action_items=[
                    f"Pass the literal CVE payload `{task.payload}` via: {inj.get('preferred_source', 'carrier / presignedUrl / URI builder')}",
                    "If GCS path: pass payload as presignedUrl argument to SnowflakeGCSClient.download when applicable.",
                    "In mocked execute(HttpUriRequest), log request.getURI() and ensure it contains the payload authority trick.",
                ],
                evidence=[str(run_summary.markers)],
                do_not_repeat=[],
                metadata={"path_id": task.path_id},
            )

        if stage in ("VULN_BEHAVIOR_NOT_OBSERVED",) or verdict.reason == "VULN_BEHAVIOR_NOT_OBSERVED":
            return DebugBoard(
                status="VULN_BEHAVIOR_NOT_OBSERVED",
                root_cause_top3=[
                    "EXTRACT_HOST marker did not match expected vulnerable host parsing.",
                    "Oracle line missing or differs from task payload; HttpClient version may not be vulnerable line.",
                ],
                action_items=[
                    "Include the compact upstream URIUtils.extractHost oracle on `new java.net.URI(task payload)` as auxiliary evidence.",
                    "If downstream URI is captured, optionally run URIUtils.extractHost on that URI -helpful but not mandatory per prompt policy.",
                    "Confirm org.apache.httpcomponents:httpclient version in pom matches vulnerable expectation for this CVE lab.",
                ],
                evidence=[str(run_summary.markers)],
                do_not_repeat=[],
                metadata={"path_id": task.path_id},
            )

        if run_summary.failure_stage == "instrumentation_failed":
            return DebugBoard(
                status="instrumentation_failed",
                root_cause_top3=[
                    "Could not match bridge line pattern for automatic instrumentation.",
                    "Bridge line drift vs CodeQL results.",
                ],
                action_items=["Inspect bridge source at reported line.", "Extend executor bridge-kind patterns if needed."],
                evidence=[str(run_summary.metadata)],
                do_not_repeat=[],
                metadata={"path_id": task.path_id},
            )

        if generation.validation_errors:
            return DebugBoard(
                status="GENERATION_INVALID",
                root_cause_top3=["Static validation rejected the generated body before compile.", str(generation.validation_errors)],
                action_items=[
                    "Follow method-body-only constraints and test_plan.code_generation_constraints.",
                    "Ensure payload literal appears and downstream/Snowflake hints are present per generator pre-check.",
                ],
                evidence=[str(generation.validation_errors)],
                do_not_repeat=list(prev.get("do_not_repeat", [])),
                metadata={"path_id": task.path_id},
            )

        return DebugBoard(
            status=verdict.reason or "UNKNOWN",
            root_cause_top3=["Review combined logs and markers.", "Compare to selected_path.method_path.", verdict.next_action],
            action_items=[verdict.next_action],
            evidence=[verdict.reason, str(run_summary.failure_stage)],
            do_not_repeat=list(prev.get("do_not_repeat", [])),
            metadata={"path_id": task.path_id, "previous": prev},
        )
    def debug(
        self,
        task: TestTask,
        prompt_package: PromptPackage,
        generation: GenerationResult,
        run_summary: RunSummary,
        verdict: Verdict,
        previous_debug_board: dict[str, Any] | None,
    ) -> DebugBoard:
        heuristic = self._heuristic_debug(
            task,
            prompt_package,
            generation,
            run_summary,
            verdict,
            previous_debug_board,
        )
        if self.llm is None:
            return heuristic

        system_prompt = _load_md("debugger_system_prompt.md") or (
            "You are DebuggerAgent. Return strict JSON matching DebugBoard."
        )
        user_payload = {
            "required_output_schema": {
                "status": "string",
                "root_cause_top3": ["string", "string", "string"],
                "action_items": ["string"],
                "evidence": ["string"],
                "do_not_repeat": ["string"],
                "metadata": "object",
            },
            "task": task.to_dict(),
            "prompt_package_digest": {
                "entry_method": prompt_package.entry_method,
                "selected_path": prompt_package.selected_path,
                "coding_contract": prompt_package.coding_contract,
                "verifier_package": prompt_package.verifier_package,
                "test_plan": prompt_package.test_plan,
                "prompt_rendered_head": str((prompt_package.metadata or {}).get("prompt_rendered") or "")[:8000],
            },
            "generation": generation.to_dict(),
            "run_summary": run_summary.to_dict(),
            "verdict": verdict.to_dict(),
            "previous_debug_board": previous_debug_board,
            "heuristic_debug_board": heuristic.to_dict(),
        }
        try:
            raw = self.llm.invoke(
                system_prompt=system_prompt,
                user_prompt=json.dumps(user_payload, ensure_ascii=False, indent=2),
                temperature=0.1,
            )
            data = json.loads(json_only_guard(raw))
        except Exception as e:
            meta = dict(heuristic.metadata)
            meta["debugger_agent_llm_error"] = str(e)
            return DebugBoard(
                status=heuristic.status,
                root_cause_top3=heuristic.root_cause_top3,
                action_items=heuristic.action_items,
                evidence=heuristic.evidence,
                do_not_repeat=heuristic.do_not_repeat,
                metadata=meta,
            )

        meta = dict(heuristic.metadata)
        extra_meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        meta.update(extra_meta)
        meta.update(
            {
                "debugger_raw_model_output": raw,
                "debugger_structured_output": data,
                "heuristic_debug_board": heuristic.to_dict(),
            }
        )
        return DebugBoard(
            status=str(data.get("status") or heuristic.status),
            root_cause_top3=_string_list(data.get("root_cause_top3"), heuristic.root_cause_top3, 3),
            action_items=_string_list(data.get("action_items"), heuristic.action_items, 8),
            evidence=_string_list(data.get("evidence"), heuristic.evidence, 8),
            do_not_repeat=_string_list(data.get("do_not_repeat"), heuristic.do_not_repeat, 12),
            metadata=meta,
        )
