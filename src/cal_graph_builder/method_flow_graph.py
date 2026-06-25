from __future__ import annotations

import json
import logging
from collections import deque
from pathlib import Path
from typing import Any

from src.cal_graph_builder.from_codeql_csv import (
    dot_escape_label,
    method_node_id,
    method_sig_part_from_full,
)

logger = logging.getLogger(__name__)


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_candidate_entry(row: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(row, dict):
        return None
    entry_sig = (
        row.get("entry_signature")
        or row.get("signature")
        or row.get("method_signature")
        or row.get("entry_sig")
        or ""
    )
    entry_type = row.get("entry_type") or row.get("declaring_type") or row.get("class_name") or ""
    entry_method = row.get("entry_method") or row.get("method") or row.get("method_name") or ""

    if isinstance(entry_sig, str) and entry_sig.strip():
        es = entry_sig.strip()
        head_before_paren = es.split("(")[0] if "(" in es else es
        if "." in head_before_paren:
            full_sig = es
        elif entry_type:
            full_sig = f"{entry_type}.{es}"
        else:
            full_sig = es
    elif entry_type and entry_method:
        full_sig = f"{entry_type}.{entry_method}"
    else:
        return None

    file_val = row.get("file") or row.get("path") or row.get("location_file") or ""
    line_val = row.get("line") or row.get("start_line") or row.get("location_line") or 0
    try:
        line_int = int(line_val)
    except (TypeError, ValueError):
        line_int = 0

    kind = row.get("entry_kind") or row.get("kind") or "unknown"

    return {
        "signature": full_sig,
        "method": entry_method or _method_from_full_sig(full_sig),
        "declaring_type": entry_type or _type_from_full_sig(full_sig),
        "file": str(file_val) if file_val is not None else "",
        "line": line_int,
        "entry_kind": str(kind),
    }


def _method_from_full_sig(full_sig: str) -> str:
    if "(" in full_sig:
        head = full_sig.split("(")[0]
        return head.split(".")[-1]
    return full_sig.split(".")[-1] if "." in full_sig else full_sig


def _type_from_full_sig(full_sig: str) -> str:
    if "(" in full_sig:
        head = full_sig.split("(")[0]
        if "." in head:
            return head.rsplit(".", 1)[0]
        return head
    if "." in full_sig:
        return full_sig.rsplit(".", 1)[0]
    return ""


def normalize_bridge_point(bp: dict[str, Any]) -> dict[str, Any]:
    enc_sig = (
        bp.get("enclosing_signature")
        or bp.get("enclosing_method_signature")
        or bp.get("method_signature")
        or ""
    )
    enc_type = bp.get("enclosing_type") or bp.get("class_name") or ""
    enc_method = bp.get("enclosing_method") or bp.get("method") or ""

    if isinstance(enc_sig, str) and enc_sig.strip():
        full_sig = enc_sig.strip()
        head_before_paren = full_sig.split("(")[0] if "(" in full_sig else full_sig
        if "." not in head_before_paren and enc_type:
            full_sig = f"{enc_type}.{full_sig}"
    elif enc_type and enc_method:
        full_sig = f"{enc_type}.{enc_method}"
    else:
        full_sig = ""

    return {
        "kind": bp.get("kind", "unknown"),
        "signature": full_sig,
        "enclosing_method": enc_method,
        "enclosing_type": enc_type,
        "file": bp.get("file", ""),
        "line": bp.get("line", 0),
        "source_query": bp.get("source_query", ""),
        "raw": bp,
    }


def _load_call_graph(path: Path) -> dict[str, Any]:
    data = _read_json(path)
    if not isinstance(data, dict):
        raise ValueError(f"call graph JSON must be an object: {path}")
    return data


def _build_adjacency(edges: list[dict[str, Any]]) -> dict[str, list[tuple[str, dict[str, Any]]]]:
    adj: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for e in edges:
        s = e.get("source")
        t = e.get("target")
        if not s or not t:
            continue
        adj.setdefault(s, []).append(
            (
                t,
                {
                    "source": s,
                    "target": t,
                    "call_file": e.get("call_file", ""),
                    "call_line": e.get("call_line", 0),
                },
            )
        )
    return adj


def _nodes_by_lookup(nodes: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    by_id: dict[str, dict[str, Any]] = {}
    sig_to_id: dict[str, str] = {}
    for n in nodes:
        nid = n.get("id")
        if not nid:
            continue
        by_id[str(nid)] = n
        sig = n.get("signature")
        if isinstance(sig, str) and sig:
            sig_to_id[sig] = str(nid)
    return by_id, sig_to_id


def _resolve_entry_node_id(
    canonical: dict[str, Any],
    sig_to_id: dict[str, str],
    by_id: dict[str, dict[str, Any]],
) -> str | None:
    dt = canonical["declaring_type"]
    meth = canonical["method"]
    sig = canonical["signature"]
    mp = method_sig_part_from_full(sig)
    nid = method_node_id(dt, meth, mp)
    if nid in by_id:
        return nid
    if sig in sig_to_id:
        return sig_to_id[sig]
    for n in by_id.values():
        if n.get("signature") == sig:
            return str(n.get("id"))
    return None


def _resolve_bridge_graph_ids(
    nb: dict[str, Any],
    by_id: dict[str, dict[str, Any]],
) -> tuple[list[str], str | None]:
    enc_type = nb["enclosing_type"]
    enc_method = nb["enclosing_method"]
    full_sig = nb["signature"]

    candidates: list[str] = []
    if full_sig and enc_type:
        mp = method_sig_part_from_full(full_sig)
        nid = method_node_id(enc_type, enc_method or _method_from_full_sig(full_sig), mp)
        if nid in by_id:
            candidates.append(nid)

    if enc_type and enc_method:
        for nid, node in by_id.items():
            if node.get("declaring_type") == enc_type and node.get("method") == enc_method:
                if nid not in candidates:
                    candidates.append(nid)

    if candidates:
        return candidates, None
    return [], "Bridge enclosing method does not match any call graph node"


def _bfs_shortest_path(
    start: str,
    goal: str,
    adj: dict[str, list[tuple[str, dict[str, Any]]]],
    max_depth: int,
) -> tuple[list[str], list[dict[str, Any]]] | None:
    if start == goal:
        return [start], []

    queue: deque[tuple[str, list[str], list[dict[str, Any]]]] = deque()
    queue.append((start, [start], []))
    visited: set[str] = {start}

    while queue:
        node, path_nodes, path_edges = queue.popleft()
        if len(path_nodes) > max_depth:
            continue
        for nbr, edge_rec in adj.get(node, []):
            new_edges = path_edges + [edge_rec]
            new_nodes = path_nodes + [nbr]
            if nbr == goal:
                return new_nodes, new_edges
            if nbr not in visited and len(new_nodes) <= max_depth + 1:
                visited.add(nbr)
                queue.append((nbr, new_nodes, new_edges))
    return None


def build_method_flow_graph(
    call_graph_json: Path,
    candidate_entries_json: Path,
    bridge_points_json: Path,
    output_dir: Path,
    max_depth: int = 30,
    max_paths_per_bridge: int = 20,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)

    cg = _load_call_graph(call_graph_json)
    case_id = str(cg.get("case_id", ""))
    downstream = str(cg.get("downstream", ""))
    nodes = cg.get("nodes") or []
    edges = cg.get("edges") or []
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise ValueError("call graph must contain nodes and edges lists")

    by_id, sig_to_id = _nodes_by_lookup(nodes)
    adj = _build_adjacency(edges)

    candidate_entries_available = True
    entry_canonicals: list[dict[str, Any]] = []
    if not candidate_entries_json.is_file():
        candidate_entries_available = False
        logger.warning("candidate_entries.json missing: %s", candidate_entries_json)
    else:
        raw_entries = _read_json(candidate_entries_json)
        if isinstance(raw_entries, dict) and "rows" in raw_entries:
            raw_entries = raw_entries["rows"]
        if not isinstance(raw_entries, list):
            candidate_entries_available = False
            logger.warning("candidate_entries.json is not a list: %s", candidate_entries_json)
        elif len(raw_entries) == 0:
            candidate_entries_available = False
            logger.warning("candidate_entries.json is empty")
        else:
            first = raw_entries[0]
            if isinstance(first, dict):
                logger.info("candidate_entries first row keys: %s", list(first.keys()))
            for row in raw_entries:
                if isinstance(row, dict):
                    c = normalize_candidate_entry(row)
                    if c:
                        entry_canonicals.append(c)

    bridge_raw = _read_json(bridge_points_json)
    if isinstance(bridge_raw, dict):
        bps = bridge_raw.get("bridge_points") or []
    elif isinstance(bridge_raw, list):
        bps = bridge_raw
    else:
        bps = []

    bridge_normalized = [normalize_bridge_point(bp) for bp in bps if isinstance(bp, dict)]

    paths_out: list[dict[str, Any]] = []
    unreachable: list[dict[str, Any]] = []
    flow_node_ids: set[str] = set()
    flow_edges: set[tuple[str, str, str, int]] = set()

    if not candidate_entries_available or not entry_canonicals:
        for nb in bridge_normalized:
            unreachable.append(
                {
                    "bridge_point": {
                        "signature": nb["signature"],
                        "file": nb["file"],
                        "line": nb["line"],
                    },
                    "reason": "candidate entries unavailable or empty",
                }
            )
        summary = {
            "entry_count": 0,
            "bridge_point_count": len(bridge_normalized),
            "reachable_bridge_point_count": 0,
            "unreachable_bridge_point_count": len(bridge_normalized),
            "path_count": 0,
            "max_depth": max_depth,
            "candidate_entries_available": False,
        }
        return _write_method_flow_outputs(
            output_dir,
            case_id,
            downstream,
            paths_out,
            unreachable,
            summary,
            flow_node_ids,
            flow_edges,
            by_id,
        )

    entry_node_ids: list[tuple[str, dict[str, Any]]] = []
    for ent in entry_canonicals:
        eid = _resolve_entry_node_id(ent, sig_to_id, by_id)
        if eid:
            entry_node_ids.append((eid, ent))

    if not entry_node_ids:
        for nb in bridge_normalized:
            unreachable.append(
                {
                    "bridge_point": {
                        "signature": nb["signature"] or f"{nb['enclosing_type']}.{nb['enclosing_method']}",
                        "file": nb["file"],
                        "line": nb["line"],
                    },
                    "reason": "No candidate entry maps to a call graph node",
                }
            )
        summary = {
            "entry_count": len(entry_canonicals),
            "bridge_point_count": len(bridge_normalized),
            "reachable_bridge_point_count": 0,
            "unreachable_bridge_point_count": len(unreachable),
            "path_count": 0,
            "max_depth": max_depth,
            "candidate_entries_available": True,
        }
        return _write_method_flow_outputs(
            output_dir,
            case_id,
            downstream,
            paths_out,
            unreachable,
            summary,
            flow_node_ids,
            flow_edges,
            by_id,
        )

    reachable_indices: set[int] = set()
    for bi, nb in enumerate(bridge_normalized):
        b_ids, fail_reason = _resolve_bridge_graph_ids(nb, by_id)
        if not b_ids:
            unreachable.append(
                {
                    "bridge_point": {
                        "signature": nb["signature"] or f"{nb['enclosing_type']}.{nb['enclosing_method']}",
                        "file": nb["file"],
                        "line": nb["line"],
                    },
                    "reason": fail_reason or "Bridge enclosing method does not match any call graph node",
                }
            )
            continue

        collected: list[tuple[int, str, list[str], list[dict[str, Any]], dict[str, Any]]] = []
        for goal in b_ids:
            for eid, ent in entry_node_ids:
                result = _bfs_shortest_path(eid, goal, adj, max_depth)
                if result:
                    node_path, edge_path = result
                    collected.append((len(node_path), eid, node_path, edge_path, ent))

        collected.sort(key=lambda x: x[0])
        kept = collected[:max_paths_per_bridge]
        if not kept:
            unreachable.append(
                {
                    "bridge_point": {
                        "signature": nb["signature"] or f"{nb['enclosing_type']}.{nb['enclosing_method']}",
                        "file": nb["file"],
                        "line": nb["line"],
                    },
                    "reason": "No candidate entry reaches the bridge enclosing method within max_depth",
                }
            )
            continue

        reachable_indices.add(bi)
        for _, _eid, node_path, edge_path, ent in kept:
            bridge_payload = {
                "kind": nb["kind"],
                "signature": nb["signature"] or f"{nb['enclosing_type']}.{nb['enclosing_method']}",
                "enclosing_method": nb["enclosing_method"],
                "enclosing_type": nb["enclosing_type"],
                "file": nb["file"],
                "line": nb["line"],
                "source_query": nb["source_query"],
            }
            node_objs = []
            for nid in node_path:
                info = by_id.get(nid, {})
                node_objs.append(
                    {
                        "signature": info.get("signature", nid),
                        "declaring_type": info.get("declaring_type", ""),
                        "method": info.get("method", ""),
                    }
                )
            for nid in node_path:
                flow_node_ids.add(nid)
            for er in edge_path:
                flow_edges.add(
                    (
                        er["source"],
                        er["target"],
                        str(er.get("call_file", "")),
                        int(er.get("call_line", 0) or 0),
                    )
                )

            paths_out.append(
                {
                    "entry": {
                        "signature": ent["signature"],
                        "method": ent["method"],
                        "declaring_type": ent["declaring_type"],
                        "file": ent["file"],
                        "line": ent["line"],
                        "entry_kind": ent["entry_kind"],
                    },
                    "bridge_point": bridge_payload,
                    "path_length": len(node_path),
                    "node_ids": node_path,
                    "nodes": node_objs,
                    "edges": edge_path,
                    "status": "reachable_by_codeql_call_graph",
                    "confidence": "method_level",
                }
            )

    summary = {
        "entry_count": len(entry_canonicals),
        "bridge_point_count": len(bridge_normalized),
        "reachable_bridge_point_count": len(reachable_indices),
        "unreachable_bridge_point_count": len(unreachable),
        "path_count": len(paths_out),
        "max_depth": max_depth,
        "candidate_entries_available": True,
    }

    return _write_method_flow_outputs(
        output_dir,
        case_id,
        downstream,
        paths_out,
        unreachable,
        summary,
        flow_node_ids,
        flow_edges,
        by_id,
    )


def _write_method_flow_outputs(
    output_dir: Path,
    case_id: str,
    downstream: str,
    paths_out: list[dict[str, Any]],
    unreachable: list[dict[str, Any]],
    summary: dict[str, Any],
    flow_node_ids: set[str],
    flow_edges: set[tuple[str, str, str, int]],
    by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    paths_payload = {
        "case_id": case_id,
        "downstream": downstream,
        "analysis_engine": "codeql",
        "graph_type": "entry_to_bridge_method_flow",
        "paths": paths_out,
        "unreachable_bridge_points": unreachable,
        "summary": summary,
    }
    (output_dir / "method_flow_paths.json").write_text(
        json.dumps(paths_payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    entry_sig_endpoints: set[str] = set()
    bridge_sig_endpoints: set[str] = set()
    for p in paths_out:
        nids = p.get("node_ids") or []
        if nids:
            entry_sig_endpoints.add(str(by_id.get(nids[0], {}).get("signature", nids[0])))
            bridge_sig_endpoints.add(str(by_id.get(nids[-1], {}).get("signature", nids[-1])))

    dot_lines = ["digraph method_flow {", "  rankdir=LR;"]
    for nid in sorted(flow_node_ids):
        info = by_id.get(nid, {})
        raw_sig = str(info.get("signature", nid))
        if raw_sig in entry_sig_endpoints:
            label = dot_escape_label(f"ENTRY: {raw_sig}", limit=400)
        elif raw_sig in bridge_sig_endpoints:
            label = dot_escape_label(f"BRIDGE: {raw_sig}", limit=400)
        else:
            label = dot_escape_label(raw_sig, limit=400)
        nid_esc = dot_escape_label(raw_sig, limit=400)
        dot_lines.append(f'  "{nid_esc}" [label="{label}"];')

    for src, tgt, cf, cl in sorted(flow_edges):
        src_sig = str(by_id.get(src, {}).get("signature", src))
        tgt_sig = str(by_id.get(tgt, {}).get("signature", tgt))
        es = dot_escape_label(src_sig, limit=400)
        et = dot_escape_label(tgt_sig, limit=400)
        elab = dot_escape_label(f"{cf}:{cl}" if cf else str(cl), limit=120)
        dot_lines.append(f'  "{es}" -> "{et}" [label="{elab}"];')

    dot_lines.append("}")
    (output_dir / "method_flow_graph.dot").write_text("\n".join(dot_lines), encoding="utf-8")

    if summary.get("candidate_entries_available"):
        if paths_out:
            mf_status = "success"
        else:
            mf_status = "no_paths_found"
    else:
        mf_status = "skipped_no_candidate_entries"

    summary_out = {
        "case_id": case_id,
        "downstream": downstream,
        "status": mf_status,
        "path_count": summary["path_count"],
        "reachable_bridge_point_count": summary["reachable_bridge_point_count"],
        "unreachable_bridge_point_count": summary["unreachable_bridge_point_count"],
        "output_dir": str(output_dir.resolve()),
        "summary": summary,
    }
    (output_dir / "method_flow_summary.json").write_text(
        json.dumps(summary_out, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    return summary_out
