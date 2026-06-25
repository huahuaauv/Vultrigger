from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.third_phase.agents.utils import json_only_guard
from src.third_phase.llm_client import LLMClient
from src.third_phase.models import RunSummary, Verdict


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


class VerifierAgent:
    """
    LLM-assisted verifier with deterministic hard-gate enforcement.
    """

    def __init__(self, llm: LLMClient | None = None) -> None:
        self.llm = llm

    def _deterministic_judge(
        self,
        run_summary: RunSummary,
        verifier_package: dict[str, Any] | None,
        *,
        smoke_only: bool = False,
    ) -> Verdict:
        _ = verifier_package
        ev: list[str] = []
        if run_summary.compile_success:
            ev.append("compile_ok")
        if run_summary.run_success:
            ev.append("run_ok")
        if run_summary.bridge_hit:
            ev.append("bridge_marker_present")
        if run_summary.payload_observed_at_bridge:
            ev.append("payload_observed_true")
        if run_summary.vulnerability_behavior_observed:
            ev.append("extract_host_matches_vulnerable_expectation")

        if smoke_only:
            ok = (
                run_summary.compile_success
                and run_summary.run_success
                and run_summary.vuln_api_invoked
                and "[AUTO-POV] EXTRACT_HOST=" in (run_summary.runtime_logs or "")
            )
            return Verdict(
                judgement="success" if ok else "fail",
                confidence="high" if ok else "medium",
                reason="SMOKE_OK" if ok else "SMOKE_INCOMPLETE",
                key_matched_evidence=ev,
                key_differences=[] if ok else ["smoke_mode_does_not_require_bridge_hit"],
                next_action="continue_full_pipeline" if ok else "fix_precheck_or_maven",
                metadata={"mode": "deterministic_smoke_only"},
            )

        if not run_summary.compile_success:
            return Verdict(
                judgement="fail",
                confidence="high",
                reason="COMPILE_FAILED",
                key_matched_evidence=ev,
                key_differences=["compile_success required"],
                next_action="fix_generation_or_maven_deps",
                metadata={},
            )
        if not run_summary.run_success:
            return Verdict(
                judgement="fail",
                confidence="high",
                reason="RUN_FAILED",
                key_matched_evidence=ev,
                key_differences=["run_success required"],
                next_action="inspect_surefire_and_runtime_logs",
                metadata={},
            )
        if not run_summary.bridge_hit:
            return Verdict(
                judgement="fail",
                confidence="high",
                reason="CHAIN_NOT_HIT",
                key_matched_evidence=ev,
                key_differences=["bridge_hit required"],
                next_action="drive_selected_entry_to_bridge",
                metadata={},
            )
        if not run_summary.payload_observed_at_bridge:
            return Verdict(
                judgement="fail",
                confidence="high",
                reason="PAYLOAD_NOT_OBSERVED",
                key_matched_evidence=ev,
                key_differences=["payload_observed_at_bridge required"],
                next_action="route_malformed_uri_into_bridge_request",
                metadata={},
            )
        if not run_summary.vulnerability_behavior_observed:
            return Verdict(
                judgement="fail",
                confidence="high",
                reason="VULN_BEHAVIOR_NOT_OBSERVED",
                key_matched_evidence=ev,
                key_differences=["vulnerability_behavior_observed required"],
                next_action="verify_httpclient_version_and_uriutils_oracle",
                metadata={},
            )

        return Verdict(
            judgement="success",
            confidence="high",
            reason="ALL_HARD_GATES_SATISFIED",
            key_matched_evidence=ev,
            key_differences=[],
            next_action="none",
            metadata={},
        )

    def judge(
        self,
        run_summary: RunSummary,
        verifier_package: dict[str, Any] | None,
        *,
        smoke_only: bool = False,
    ) -> Verdict:
        deterministic = self._deterministic_judge(
            run_summary,
            verifier_package,
            smoke_only=smoke_only,
        )
        if self.llm is None:
            return deterministic

        system_prompt = _load_md("verifier_system_prompt.md") or (
            "You are VerifierAgent. Return strict JSON matching Verdict."
        )
        user_payload = {
            "required_output_schema": {
                "judgement": "success|fail; must match deterministic_verdict",
                "confidence": "low|medium|high",
                "reason": "string; must not contradict deterministic_verdict.reason",
                "key_matched_evidence": ["string"],
                "key_differences": ["string"],
                "next_action": "string",
                "metadata": "object",
            },
            "hard_gate_policy": "The deterministic verdict controls judgement and reason. Explain it; do not override it.",
            "run_summary": run_summary.to_dict(),
            "verifier_package": verifier_package or {},
            "smoke_only": smoke_only,
            "deterministic_verdict": deterministic.to_dict(),
        }
        try:
            raw = self.llm.invoke(
                system_prompt=system_prompt,
                user_prompt=json.dumps(user_payload, ensure_ascii=False, indent=2),
                temperature=0.0,
            )
            data = json.loads(json_only_guard(raw))
        except Exception as e:
            meta = dict(deterministic.metadata)
            meta["verifier_agent_llm_error"] = str(e)
            return Verdict(
                judgement=deterministic.judgement,
                confidence=deterministic.confidence,
                reason=deterministic.reason,
                key_matched_evidence=deterministic.key_matched_evidence,
                key_differences=deterministic.key_differences,
                next_action=deterministic.next_action,
                metadata=meta,
            )

        meta = dict(deterministic.metadata)
        extra_meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        meta.update(extra_meta)
        meta.update(
            {
                "verifier_raw_model_output": raw,
                "verifier_structured_output": data,
                "deterministic_verdict": deterministic.to_dict(),
                "hard_gates_enforced": True,
            }
        )
        confidence = str(data.get("confidence") or deterministic.confidence)
        if confidence not in {"low", "medium", "high"}:
            confidence = deterministic.confidence
        return Verdict(
            judgement=deterministic.judgement,
            confidence=confidence,
            reason=deterministic.reason,
            key_matched_evidence=_string_list(
                data.get("key_matched_evidence"), deterministic.key_matched_evidence, 12
            ),
            key_differences=_string_list(data.get("key_differences"), deterministic.key_differences, 12),
            next_action=str(data.get("next_action") or deterministic.next_action),
            metadata=meta,
        )
