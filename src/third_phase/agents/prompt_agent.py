from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from src.third_phase.agents.utils import json_only_guard
from src.third_phase.context_ranker import build_test_environment_facts
from src.third_phase.llm_client import LLMClient
from src.third_phase.models import ContextPack, PromptPackage, TestTask


def _load_md(name: str) -> str:
    p = Path(__file__).resolve().parents[1] / "templates" / name
    if p.is_file():
        return p.read_text(encoding="utf-8")
    return ""


def _default_verifier_package(task: TestTask) -> dict[str, Any]:
    return {
        "success_criteria": {
            "compile_success": True,
            "run_success": True,
            "bridge_hit": True,
            "payload_observed_at_bridge": True,
            "vulnerability_behavior_observed": True,
        },
        "required_markers": [
            "[AUTO-POV] HIT_BRIDGE_POINT",
            "[AUTO-POV] PAYLOAD_OBSERVED=true",
            "[AUTO-POV] EXTRACT_HOST=",
        ],
        "payload": task.payload,
        "expected_vulnerable_host": task.oracle.get("expected_vulnerable_host"),
        "failure_stages": [
            "COMPILE_FAILED",
            "PRECHECK_FAILED",
            "RUN_FAILED",
            "instrumentation_failed",
            "CHAIN_NOT_HIT",
            "PAYLOAD_NOT_OBSERVED",
            "VULN_BEHAVIOR_NOT_OBSERVED",
            "VERIFIER_UNCERTAIN",
        ],
    }


def get_required_runtime_markers(task: TestTask) -> list[str]:
    return list(_default_verifier_package(task)["required_markers"])


def _compact_api_facts_for_llm(api_facts: dict[str, Any]) -> dict[str, Any]:
    """Compact api_facts before sending them to the model."""
    d = copy.deepcopy(api_facts)
    ec = d.get("entry_class")
    if isinstance(ec, dict):
        pm = ec.get("public_methods") or []
        if isinstance(pm, list) and len(pm) > 35:
            ec["public_methods"] = pm[:35]
            ec["public_methods_omitted_count"] = len(pm) - 35
    bec = d.get("bridge_enclosing_class")
    if isinstance(bec, dict):
        pm = bec.get("public_methods") or []
        if isinstance(pm, list) and len(pm) > 35:
            bec["public_methods"] = pm[:35]
            bec["public_methods_omitted_count"] = len(pm) - 35
    eu = d.get("existing_test_usage")
    if isinstance(eu, dict):
        at = eu.get("assembly_templates") or []
        if isinstance(at, list) and len(at) > 15:
            eu["assembly_templates"] = at[:15]
            eu["assembly_templates_omitted_count"] = len(at) - 15
    tf = d.get("test_framework")
    if isinstance(tf, dict) and tf.get("surefire_snippet"):
        ss = str(tf["surefire_snippet"])
        if len(ss) > 1200:
            tf["surefire_snippet"] = ss[:1200] + "..."
    return d


def _snippet_block(context_pack: ContextPack, limit: int = 22) -> str:
    parts: list[str] = []
    for i, sn in enumerate(context_pack.snippets[:limit], start=1):
        f = sn.get("file", "")
        k = sn.get("kind", "")
        sl = sn.get("start_line", "")
        el = sn.get("end_line", "")
        tx = str(sn.get("text") or "").strip()
        parts.append(f"--- Snippet {i} [{k}] {f}:{sl}-{el} ---\n{tx}")
    return "\n\n".join(parts)


def _render_generator_prompt(
    task: TestTask,
    test_plan: dict[str, Any],
    context_pack: ContextPack,
    api_facts: dict[str, Any],
    verifier_package: dict[str, Any],
    previous_debug_board: dict[str, Any] | None,
) -> str:
    markers = verifier_package.get("required_markers") or []
    markers_txt = "\n".join(f"- {m}" for m in markers)
    env_facts = build_test_environment_facts(api_facts)
    upstream = test_plan.get("upstream_poc_reference") or {}
    selected_summary = test_plan.get("selected_path_summary") or {}
    strategy_steps = test_plan.get("recommended_strategy_steps") or []
    steps_txt = "\n".join(f"{i+1}. {s}" for i, s in enumerate(strategy_steps))
    pitfalls = test_plan.get("known_pitfalls") or []
    pitfalls_txt = "\n".join(f"- {p}" for p in pitfalls)
    ctx_block = _snippet_block(context_pack, limit=18)
    api_compact = _compact_api_facts_for_llm(api_facts)

    prev = ""
    if previous_debug_board:
        prev = "\n\nPrevious debug feedback (address if still relevant):\n" + json.dumps(
            previous_debug_board, ensure_ascii=False, indent=2
        )

    sf_recipe = test_plan.get("snowflake_gcs_verified_recipe")
    recipe_priority = ""
    if isinstance(sf_recipe, dict) and sf_recipe.get("minimal_skeleton_all_fqn"):
        recipe_priority = (
            "\n>>> SNOWFLAKE GCS -HIGHEST PRIORITY <<<\n"
            "The JSON field `snowflake_gcs_verified_recipe.minimal_skeleton_all_fqn` is a fully-qualified working skeleton "
            "(same pattern as SnowflakeGCSClientCve202013956PathTest). Start from it and only adjust names/formatting if needed.\n"
            "Hard rules: use SnowflakeGCSClient.createSnowflakeGCSClient(...); mockStatic net.snowflake.client.core.HttpUtil "
            "(never jdbc.HttpUtil); HttpClientSettingsKey on SFSession.getHttpClientKey(); do not rely on `new SnowflakeGCSClient()`.\n\n"
        )

    return f"""You are a Java/JUnit test generation agent.

Your task is to generate ONLY the body of one JUnit test method (already inside `ThirdPhasePOVTest#testCVE202013956SelectedPath`).
The test should attempt to dynamically validate a candidate downstream trigger path for the CVE.
{recipe_priority}
High-level goal:
- Prefer calling the selected downstream entry (or a directly relevant downstream method) described in the test plan.
- Inject the CVE payload through the planned downstream source (see payload_injection_plan).
- Avoid real network access by using mocks or fakes.
- Try to make the payload reach the selected bridge so instrumentation can observe it.
- Print the AUTO-POV evidence markers required by the verifier (see below).
- You may use the upstream PoC as a behavioral reference for the vulnerability oracle. A compact upstream-style URIUtils.extractHost oracle is acceptable as auxiliary evidence, especially if capturing the downstream URI is difficult -but still attempt the downstream path first when feasible.

Do not output:
- package declaration
- import statements
- class declaration
- @Test annotation
- markdown fences

Important code rule:
The generated code will be inserted into an existing test class. If a class is not already imported by the template, use its fully qualified name. The template currently imports:
{json.dumps(env_facts.get("template_imports") or [], ensure_ascii=False, indent=2)}

Output format for your answer:
- Return **strict JSON only** with keys `method_body` (plain Java statements) and/or `method_body_b64` (base64 UTF-8), as required by the project generator.

Verifier-oriented log markers (substring presence; exact strings used by instrumentation / logs):
{markers_txt}

Expected vulnerable host for oracle: {task.oracle.get("expected_vulnerable_host")}

--- Selected test plan (JSON) ---
{json.dumps(test_plan, ensure_ascii=False, indent=2)}

--- Selected downstream path summary ---
{json.dumps(selected_summary, ensure_ascii=False, indent=2)}

--- Payload facts ---
{json.dumps(test_plan.get("payload") or {}, ensure_ascii=False, indent=2)}

--- Upstream PoC reference (allowed) ---
{json.dumps(upstream, ensure_ascii=False, indent=2)}

--- Relevant downstream / project code context (rank-ordered) ---
{ctx_block}

--- Test environment facts ---
{json.dumps(env_facts, ensure_ascii=False, indent=2)}

--- api_facts (structured, compact) ---
{json.dumps(api_compact, ensure_ascii=False, indent=2)}

--- Recommended implementation strategy ---
{steps_txt if steps_txt else "(follow test_plan.payload_injection_plan and entry_invocation_plan)"}

--- Common pitfalls ---
{pitfalls_txt}
- Avoid relying only on a standalone upstream PoC if you can call the downstream entry first.
- Prefer deriving or observing the URI through the downstream path first.
- A standalone upstream PoC-style oracle may be included as auxiliary evidence if it helps satisfy the vulnerability marker.

--- Parameter flow (may be partial) ---
{json.dumps(task.parameter_flow or {}, ensure_ascii=False, indent=2)}

--- Bridge point ---
{json.dumps(task.bridge_point or {}, ensure_ascii=False, indent=2)}
{prev}

Now generate only the JSON object containing the Java method body.
"""


def _merge_verifier_package(base: dict[str, Any], patch: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(patch, dict):
        return base
    merged = copy.deepcopy(base)
    for key, value in patch.items():
        if key == "success_criteria":
            # Hard gates stay deterministic; the planner may add metadata but not loosen gates.
            continue
        if key == "required_markers" and isinstance(value, list):
            existing = list(merged.get("required_markers") or [])
            for item in value:
                if isinstance(item, str) and item and item not in existing:
                    existing.append(item)
            merged["required_markers"] = existing
            continue
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value
    return merged

class PromptAgent:
    def __init__(self, llm: LLMClient | None = None) -> None:
        self.llm = llm

    def _llm_refine_prompt_package(
        self,
        *,
        task: TestTask,
        context_pack: ContextPack,
        api_facts: dict[str, Any],
        previous_debug_board: dict[str, Any] | None,
        test_plan: dict[str, Any],
        rendered: str,
        coding_contract: str,
        verifier_package: dict[str, Any],
    ) -> tuple[str, str, dict[str, Any], dict[str, Any]]:
        if self.llm is None:
            return rendered, coding_contract, verifier_package, {}

        system_prompt = (
            (_load_md("prompt_agent_template.md") + "\n\n")
            + "You are PromptAgent. Refine the generator prompt for one fixed selected path. "
            + "Return strict JSON only. Do not choose a different path. Do not loosen verifier hard gates."
        )
        user_payload = {
            "required_output_schema": {
                "generator_prompt_addendum": "string: concise extra instructions to append to the default generator prompt",
                "coding_contract_addendum": "string: optional extra method-body constraints",
                "verifier_package_patch": "object: optional additions such as required_markers or metadata; never relax success_criteria",
                "planning_notes": ["string"],
            },
            "task": task.to_dict(),
            "test_plan": test_plan,
            "context_digest": {
                "files": context_pack.files[:40],
                "methods": context_pack.methods[:40],
                "notes": context_pack.notes,
                "snippet_count": len(context_pack.snippets),
            },
            "context_snippets_head": context_pack.snippets[:10],
            "api_facts_compact": _compact_api_facts_for_llm(api_facts),
            "previous_debug_board": previous_debug_board,
            "default_generator_prompt": rendered[:30000],
            "default_coding_contract": coding_contract,
            "default_verifier_package": verifier_package,
        }
        try:
            raw = self.llm.invoke(
                system_prompt=system_prompt,
                user_prompt=json.dumps(user_payload, ensure_ascii=False, indent=2),
                temperature=0.1,
            )
            data = json.loads(json_only_guard(raw))
        except Exception as e:
            return rendered, coding_contract, verifier_package, {
                "prompt_agent_llm_error": str(e),
            }

        refined = rendered
        replacement = str(data.get("generator_prompt_text") or "").strip()
        addendum = str(data.get("generator_prompt_addendum") or "").strip()
        if replacement:
            refined = replacement
            if task.payload and task.payload not in refined:
                refined += "\n\n--- Required default prompt guard ---\n" + rendered
        elif addendum:
            refined += "\n\n--- PromptAgent LLM refinement ---\n" + addendum

        contract_addendum = str(data.get("coding_contract_addendum") or "").strip()
        if contract_addendum:
            coding_contract += "\n8) PromptAgent LLM refinement:\n" + contract_addendum + "\n"

        verifier_package = _merge_verifier_package(
            verifier_package,
            data.get("verifier_package_patch") if isinstance(data.get("verifier_package_patch"), dict) else None,
        )
        return refined, coding_contract, verifier_package, {
            "prompt_agent_raw_model_output": raw,
            "prompt_agent_structured_output": data,
        }

    def build_prompt_package(
        self,
        task: TestTask,
        context_pack: ContextPack,
        api_facts: dict[str, Any],
        previous_debug_board: dict[str, Any] | None = None,
        *,
        test_plan: dict[str, Any] | None = None,
    ) -> PromptPackage:
        tpl = _load_md("prompt_agent_template.md")
        tp = test_plan or {}
        oracle_lines = (
            f'java.net.URI malformed = new java.net.URI("{task.payload}");\n'
            f"org.apache.http.HttpHost host = org.apache.http.client.utils.URIUtils.extractHost(malformed);\n"
            f'System.out.println("[AUTO-POV] EXTRACT_HOST=" + host.getHostName());\n'
        )
        coding_contract = (
            "1) Output JSON only from Generator: method_body or method_body_b64.\n"
            "2) Generator emits ONLY inner statements for void testCVE202013956SelectedPath() throws Exception -no package/import/class/@Test.\n"
            "3) Must embed exact payload string or new URI(\"<payload>\").\n"
            "4) Prefer the selected downstream entry per test_plan; use api_facts for types/constructors/methods.\n"
            "5) No real network; no Thread.sleep loops; no Snowflake cloud calls; do not edit src/main sources.\n"
            "6) Upstream oracle (auxiliary, encouraged when helpful):\n"
            f"{oracle_lines}"
            "7) Verifier hard gates remain: compile, run, bridge instrumentation hit, payload observed at bridge, vulnerable host oracle -see test_plan.assertion_plan.\n"
        )
        system_prompt = (
            (tpl + "\n\n" if tpl else "")
            + "You are the prompt planner for a downstream-focused JUnit generator. "
            "Paths are fixed by selected_test_paths.json -never re-rank or substitute paths. "
            "The structured test_plan is authoritative for test intent.\n"
        )
        digest = {
            "snippet_count": len(context_pack.snippets),
            "files": context_pack.files[:40],
            "notes": context_pack.notes,
        }
        verifier_package = _default_verifier_package(task)
        rendered = _render_generator_prompt(
            task, tp, context_pack, api_facts, verifier_package, previous_debug_board
        )
        rendered, coding_contract, verifier_package, prompt_llm_meta = self._llm_refine_prompt_package(
            task=task,
            context_pack=context_pack,
            api_facts=api_facts,
            previous_debug_board=previous_debug_board,
            test_plan=tp,
            rendered=rendered,
            coding_contract=coding_contract,
            verifier_package=verifier_package,
        )
        user_obj: dict[str, Any] = {
            "role": "prompt_planner_digest",
            "path_id": task.path_id,
            "case_id": task.case_id,
            "test_plan": tp,
            "context_digest": digest,
            "context_snippets_head": context_pack.snippets[:8],
            "verifier_package": verifier_package,
            "previous_failure": previous_debug_board,
        }
        user_prompt = json.dumps(user_obj, ensure_ascii=False, indent=2)
        meta = {
            "path_id": task.path_id,
            "case_id": task.case_id,
            "prompt_rendered": rendered,
            "generator_prompt_text": rendered,
            "test_plan": tp,
            **prompt_llm_meta,
        }
        return PromptPackage(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            entry_method=str(task.entry.get("signature") or ""),
            selected_path=task.selected_path_raw,
            coding_contract=coding_contract,
            oracle_spec=dict(task.oracle),
            verifier_package=verifier_package,
            test_plan=tp,
            metadata=meta,
        )
