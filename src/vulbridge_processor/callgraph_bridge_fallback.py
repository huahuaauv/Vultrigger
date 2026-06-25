from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.cal_graph_builder.from_codeql_csv import method_sig_part_from_full


def _canonical_to_java_sig(s: str) -> str:
    t = (s or "").strip()
    if "#" in t:
        a, b = t.split("#", 1)
        return f"{a.strip()}.{b.strip()}"
    return t


def _hint_matches_node_signature(hint: str, node_sig: str) -> bool:
    h = hint.strip().replace("#", ".").replace(" ", "")
    ns = (node_sig or "").replace(" ", "")
    if not h or not ns:
        return False
    if h == ns:
        return True
    if h in ns:
        return True
    if "(" not in h and "(" in ns:
        if ns.startswith(h + "("):
            return True
        if h + "(" in ns:
            return True
    return False


def _collect_hints(case: dict[str, Any], downstream: dict[str, Any]) -> list[str]:
    seen: list[str] = []
    for src in (
        downstream.get("bridge_hints") or [],
        case.get("bridge_api_canonical_names") or [],
        case.get("bridge_hints") or [],
    ):
        for x in src:
            s = str(x).strip()
            if not s:
                continue
            cj = _canonical_to_java_sig(s)
            for cand in (s, cj):
                if cand and cand not in seen:
                    seen.append(cand)
    return seen


def find_callgraph_nodes_for_bridge_hints(
    call_graph: dict[str, Any],
    hints: list[str],
) -> list[dict[str, Any]]:
    nodes = call_graph.get("nodes") or []
    if not isinstance(nodes, list) or not hints:
        return []
    matched: list[dict[str, Any]] = []
    used_sigs: set[str] = set()
    for node in nodes:
        if not isinstance(node, dict):
            continue
        sig = str(node.get("signature") or "").strip()
        if not sig or sig in used_sigs:
            continue
        for h in hints:
            if _hint_matches_node_signature(h, sig):
                matched.append(node)
                used_sigs.add(sig)
                break
    return matched


def bridge_dict_from_callgraph_node(node: dict[str, Any]) -> dict[str, Any]:
    files = node.get("files") or []
    lines = node.get("lines") or []
    file0 = str(files[0]) if files else ""
    line0 = 0
    if lines:
        try:
            line0 = int(lines[0])
        except (TypeError, ValueError):
            line0 = 0
    sig = str(node.get("signature") or "").strip()
    decl = str(node.get("declaring_type") or "").strip()
    return {
        "kind": "direct",
        "confidence": "callgraph_metadata_fallback",
        "file": file0,
        "line": line0,
        "enclosing_type": decl,
        "enclosing_method": method_sig_part_from_full(sig) if sig else str(node.get("method") or ""),
        "method_signature": sig,
        "callee_signature": sig,
        "argument": "",
        "source_query": "CallGraphBridgeFallback",
    }


def merge_callgraph_fallback_into_bridge_doc(
    bridge_doc: dict[str, Any],
    call_graph_path: Path,
    case: dict[str, Any],
    downstream: dict[str, Any],
) -> dict[str, Any]:
    summary = bridge_doc.get("summary") or {}
    total = int(summary.get("total_bridge_points", 0) or 0)
    if total > 0:
        return bridge_doc
    if not call_graph_path.is_file():
        return bridge_doc
    hints = _collect_hints(case, downstream)
    if not hints:
        return bridge_doc
    try:
        cg = json.loads(call_graph_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return bridge_doc
    nodes = find_callgraph_nodes_for_bridge_hints(cg, hints)
    if not nodes:
        return bridge_doc
    existing = list(bridge_doc.get("bridge_points") or [])
    for n in nodes:
        existing.append(bridge_dict_from_callgraph_node(n))
    direct_n = int(summary.get("direct_bridge_points", 0) or 0) + len(nodes)
    bridge_doc["bridge_points"] = existing
    bridge_doc["summary"] = {
        **summary,
        "direct_bridge_points": direct_n,
        "callgraph_fallback_bridge_points": len(nodes),
        "total_bridge_points": len(existing),
    }
    return bridge_doc


def write_bridge_doc(path: Path, bridge_doc: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bridge_doc, ensure_ascii=False, indent=2), encoding="utf-8")
