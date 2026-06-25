from __future__ import annotations

import base64
import json
import re
from typing import Any

from src.third_phase.agents.utils import json_only_guard
from src.third_phase.llm_client import LLMClient
from src.third_phase.models import ContextPack, GenerationResult, PromptPackage


_FORBIDDEN = re.compile(
    r"(package\s+|import\s+|public\s+class|@Test|```)",
    re.IGNORECASE | re.MULTILINE,
)


class GeneratorAgent:
    def __init__(self, llm: LLMClient | None) -> None:
        self.llm = llm

    def _validate_body(self, body: str, task_payload: str, bridge_hint: str) -> tuple[bool, list[str]]:
        errs: list[str] = []
        if not body.strip():
            return False, ["empty_method_body"]
        if _FORBIDDEN.search(body):
            errs.append("forbidden_token_package_import_class_test_fence")
        low = body.lower()
        if "http://" in body or "https://" in body:
            if any(x in low for x in ("new url(", "openconnection", "socket(", "httpclient.execute(")):
                errs.append("possible_real_network_pattern")
        if "thread.sleep" in low and re.search(r"thread\.sleep\s*\(\s*\d{4,}", low):
            errs.append("long_thread_sleep")
        if task_payload and task_payload not in body and "new java.net.URI" not in body and "new URI" not in body:
            errs.append("payload_literal_missing")
        if bridge_hint:
            tokens = {bridge_hint.lower()}
            for part in bridge_hint.replace("$", ".").split("."):
                if len(part) > 2:
                    tokens.add(part.lower())
            if not any(t in low for t in tokens if t):
                if not any(k in low for k in ("restrequest", "httpget", "httppost", "httprequest", "uribuilder", "snowflake")):
                    errs.append("bridge_or_carrier_hint_missing")
        return not errs, errs

    def generate_test(
        self,
        prompt_package: PromptPackage,
        api_facts: dict[str, Any],
        context_pack: ContextPack,
        debug_board: dict[str, Any] | None,
        *,
        generator_system_prompt: str,
        task_payload: str,
        bridge_carrier_hint: str,
    ) -> GenerationResult:
        if self.llm is None:
            return GenerationResult(
                success=False,
                test_file_relpath="src/test/java/auto/gen/pov/ThirdPhasePOVTest.java",
                test_class_name="ThirdPhasePOVTest",
                test_method_name="testCVE202013956SelectedPath",
                method_body="",
                method_body_b64="",
                validated_ok=False,
                validation_errors=["llm_not_configured"],
                raw_model_output="",
                metadata={"debug_board": debug_board or {}},
            )
        sys_p = (generator_system_prompt or "").strip() + "\n\n" + prompt_package.system_prompt
        user = (prompt_package.metadata or {}).get("generator_prompt_text") or ""
        if not user.strip():
            payload_obj: dict[str, Any] = {
                "prompt_package": prompt_package.to_dict(),
                "api_facts": api_facts,
                "debug_board": debug_board,
                "context_digest": {"snippet_count": len(context_pack.snippets)},
            }
            user = json.dumps(payload_obj, ensure_ascii=False, indent=2)
        raw = self.llm.invoke(system_prompt=sys_p, user_prompt=user, temperature=0.15)
        try:
            data = json.loads(json_only_guard(raw))
        except json.JSONDecodeError:
            return GenerationResult(
                success=False,
                test_file_relpath="src/test/java/auto/gen/pov/ThirdPhasePOVTest.java",
                test_class_name="ThirdPhasePOVTest",
                test_method_name="testCVE202013956SelectedPath",
                method_body="",
                method_body_b64="",
                validated_ok=False,
                validation_errors=["json_parse_failed"],
                raw_model_output=raw,
                metadata={},
            )

        body = str(data.get("method_body") or "").strip()
        b64 = str(data.get("method_body_b64") or "").strip()
        if b64:
            try:
                body = base64.b64decode(b64).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                pass
        ok, errs = self._validate_body(body, task_payload, bridge_carrier_hint)
        return GenerationResult(
            success=ok,
            test_file_relpath="src/test/java/auto/gen/pov/ThirdPhasePOVTest.java",
            test_class_name="ThirdPhasePOVTest",
            test_method_name="testCVE202013956SelectedPath",
            method_body=body,
            method_body_b64=b64,
            validated_ok=ok,
            validation_errors=errs,
            raw_model_output=raw,
            metadata={},
        )
