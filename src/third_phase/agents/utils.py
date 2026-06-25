from __future__ import annotations

import re


def json_only_guard(text: str) -> str:
    """
    尽量从模型输出中提取 JSON（容忍模型在前后输出解释文字）。
    """
    s = text.strip()
    if not s:
        return "{}"

    m = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", s, flags=re.IGNORECASE)
    if m:
        cand = m.group(1).strip()
        if "{" in cand and "}" in cand:
            return cand

    first = s.find("{")
    last = s.rfind("}")
    if first >= 0 and last > first:
        return s[first : last + 1]
    return "{}"
