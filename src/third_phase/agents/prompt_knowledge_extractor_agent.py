from __future__ import annotations

import json
from typing import Any, Dict

from ..llm_client import LLMClient
from ..prompt_knowledge import read_poc_assets
from .utils import json_only_guard


class PromptKnowledgeExtractorAgent:
    """
    LLM 主导的 PoC/README 结构化知识抽取器。
    """

    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    def extract(self, manifest: Dict[str, Any], vuln_info: Dict[str, Any]) -> Dict[str, Any]:
        assets = read_poc_assets(manifest)
        system_prompt = (
            "你是漏洞知识抽取智能体。"
            "请从给定 PoC.java 与 README 原文中抽取可执行的漏洞触发知识，输出精简 JSON。"
            "只输出严格 JSON，不要输出任何额外文本。"
        )
        user_payload = {
            "sample_id": manifest.get("id") if isinstance(manifest, dict) else "",
            "vuln_info": {
                "vuln_name": vuln_info.get("vuln_name") or vuln_info.get("title") or "",
                "cwe": vuln_info.get("cwe") or "",
            },
            "poc_assets": assets,
            "required_output_schema": {
                "vuln_profile": {"id": "string", "vuln_name": "string", "cwe": "string", "oracle_hint": "string"},
                "poc_sources": {"poc_root": "string", "poc_java": "string", "poc_readme": "string"},
                "poc_signals": {
                    "java_keyword_lines": ["string <= 240 chars"],
                    "readme_keyword_lines": ["string <= 240 chars"],
                    "invocation_candidates": ["string"],
                },
                "trigger_conditions": ["string <= 180 chars"],
            },
        }
        raw = self.llm.invoke(system_prompt=system_prompt, user_prompt=json.dumps(user_payload, ensure_ascii=False), temperature=0.2)
        data = json.loads(json_only_guard(raw))
        if "poc_sources" not in data:
            data["poc_sources"] = {
                "poc_root": assets.get("poc_root", ""),
                "poc_java": assets.get("poc_java_path", ""),
                "poc_readme": assets.get("poc_readme_path", ""),
            }
        if "vuln_profile" not in data:
            data["vuln_profile"] = {
                "id": manifest.get("id") if isinstance(manifest, dict) else "",
                "vuln_name": vuln_info.get("vuln_name") or vuln_info.get("title") or "",
                "cwe": vuln_info.get("cwe") or "",
                "oracle_hint": assets.get("oracle_hint") or "",
            }
        data["_raw_model_output"] = raw
        return data
