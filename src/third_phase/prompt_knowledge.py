from __future__ import annotations


def build_prompt_knowledge(case_info: dict) -> dict:
    return {"case_id": case_info.get("case_id", ""), "knowledge": []}
