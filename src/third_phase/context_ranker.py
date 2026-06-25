from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from src.third_phase.context_retriever import _snippet_window
from src.third_phase.models import ContextPack, TestTask


def _est_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def _priority(
    sn: dict[str, Any],
    task: TestTask,
    test_plan: dict[str, Any],
    path_sigs: set[str],
) -> tuple[int, int]:
    """
    Return (primary, secondary) for sorting — higher is earlier in pack.
    """
    kind = str(sn.get("kind") or "")
    meta = sn.get("meta") or {}
    sig = str(meta.get("signature") or "")
    f = str(sn.get("file") or "")
    text = str(sn.get("text") or "")

    pri = 0
    if kind == "entry_method" or kind == "entry_method_resolved":
        pri = 100
    elif kind == "bridge_point":
        pri = 98
    elif kind == "method_path" and sig in path_sigs:
        pri = 88
    elif kind == "method_path":
        pri = 72
    elif kind == "parameter_flow_node":
        pri = 65
    elif kind == "existing_test_usage":
        pri = 45
    elif kind == "pom_header":
        pri = 15

    # Boost snippets that mention plan keywords
    blob = (f + " " + text).lower()
    for kw, bump in (
        ("presignedurl", 6),
        ("snowflakegcsclient", 8),
        ("restrequest", 5),
        ("closeablehttpclient", 5),
        ("execute(", 3),
        ("mockito", 2),
        ("httpget", 2),
        ("uribuilder", 2),
    ):
        if kw in blob:
            pri += bump

    sec = -len(text)  # shorter after same pri, or prefer longer context? Prefer longer for code: use line span
    sl = int(sn.get("start_line") or 0)
    el = int(sn.get("end_line") or 0)
    sec = -(el - sl + 1)
    return (pri, sec)


def _collect_path_signatures(task: TestTask, test_plan: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for n in task.method_path or []:
        if isinstance(n, dict):
            s = str(n.get("signature") or "").strip()
            if s:
                out.add(s)
    for s in test_plan.get("selected_path_summary", {}).get("path_nodes") or []:
        if isinstance(s, str) and s.strip():
            out.add(s.strip())
    return out


def expand_critical_snippets(task: TestTask, project_root: Path, radius: int = 70) -> list[dict[str, Any]]:
    """Add larger-window snippets for entry and bridge (full-ish method context)."""
    extra: list[dict[str, Any]] = []
    bp = task.bridge_point
    bf = str(bp.get("file") or "")
    bl = int(bp.get("line") or 0)
    if bf and bl > 0:
        p = project_root / bf.replace("/", os.sep)
        sn = _snippet_window(p, bl, radius, "bridge_method_expanded", {"role": "bridge_method_body_context"})
        if sn:
            extra.append(sn)
    ent = task.entry
    ef = str(ent.get("file") or "")
    el = int(ent.get("line") or 0)
    if ef and el > 0:
        p = project_root / ef.replace("/", os.sep)
        sn = _snippet_window(p, el, radius, "entry_method_expanded", {"signature": ent.get("signature")})
        if sn:
            extra.append(sn)
    return extra


def rank_context_for_generation(
    task: TestTask,
    test_plan: dict[str, Any],
    raw_pack: ContextPack,
    *,
    project_root: Path,
) -> tuple[ContextPack, list[dict[str, Any]], dict[str, Any]]:
    """
    Re-order snippets for LLM consumption and emit a manifest for auditing.
    """
    path_sigs = _collect_path_signatures(task, test_plan)
    snippets = list(raw_pack.snippets)
    snippets.extend(expand_critical_snippets(task, project_root))

    scored: list[tuple[tuple[int, int], dict[str, Any]]] = []
    for sn in snippets:
        pr = _priority(sn, task, test_plan, path_sigs)
        scored.append((pr, sn))

    scored.sort(key=lambda x: x[0], reverse=True)
    # de-dupe by (file, kind, start_line, end_line)
    seen: set[tuple[Any, ...]] = set()
    ordered: list[dict[str, Any]] = []
    for _, sn in scored:
        key = (sn.get("file"), sn.get("kind"), sn.get("start_line"), sn.get("end_line"))
        if key in seen:
            continue
        seen.add(key)
        ordered.append(sn)
        if len(ordered) >= 40:
            break

    manifest: list[dict[str, Any]] = []
    for i, sn in enumerate(ordered):
        rel = str(sn.get("file") or "")
        kind = str(sn.get("kind") or "")
        reason = {
            "entry_method": "Selected path entry implementation context",
            "entry_method_resolved": "Resolved entry method location",
            "entry_method_expanded": "Expanded window around entry for constructor/call graph",
            "bridge_point": "Bridge line neighborhood from static analysis",
            "bridge_method_expanded": "Expanded window around bridge for URI/execute handling",
            "method_path": "Intermediate node on static method path",
            "parameter_flow_node": "Parameter propagation hint",
            "existing_test_usage": "Project-native test/mocking pattern",
            "pom_header": "Dependency / test plugin hints",
        }.get(kind, "Supporting context")
        relation = (
            "entry" if "entry" in kind else "bridge" if "bridge" in kind else "path" if "method" in kind or "parameter" in kind else "project"
        )
        manifest.append(
            {
                "priority_rank": i + 1,
                "file": rel,
                "kind": kind,
                "start_line": sn.get("start_line"),
                "end_line": sn.get("end_line"),
                "reason_selected": reason,
                "relation_to_selected_path": relation,
                "token_estimate": _est_tokens(str(sn.get("text") or "")),
                "meta": sn.get("meta") or {},
            }
        )

    notes = list(raw_pack.notes)
    notes.insert(
        0,
        "Context ordering: test_plan-driven ranking (entry/bridge/method_path first, then flow nodes, tests, POM).",
    )
    ranked = ContextPack(
        files=sorted({str(s.get("file") or "") for s in ordered if s.get("file")}),
        methods=list(raw_pack.methods),
        snippets=ordered,
        notes=notes,
        metadata={
            **(raw_pack.metadata or {}),
            "ranking": "test_plan_v1",
            "snippet_count_ranked": len(ordered),
        },
    )
    ranked_meta = {
        "path_id": task.path_id,
        "path_profile": test_plan.get("path_profile"),
        "snippet_order_policy": "priority(entry,bridge,method_path,parameter_flow,existing_tests,pom)",
        "total_snippets": len(ordered),
    }
    return ranked, manifest, ranked_meta


def build_test_environment_facts(api_facts: dict[str, Any]) -> dict[str, Any]:
    tf = api_facts.get("test_framework") or {}
    return {
        "junit": tf.get("junit"),
        "mockito_available": tf.get("mockito_available"),
        "httpclient_version_hints": tf.get("httpclient_version_hints"),
        "surefire_snippet": tf.get("surefire_snippet"),
        "template_imports": api_facts.get("template_imports", []),
        "assembly_templates_count": len((api_facts.get("existing_test_usage") or {}).get("assembly_templates") or []),
    }
