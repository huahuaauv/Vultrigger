from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
from typing import Any, Tuple

logger = logging.getLogger(__name__)


def dot_escape_label(s: str, limit: int = 200) -> str:
    t = (
        (s or "")
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", " ")
        .replace("\r", " ")
    )
    if len(t) > limit:
        t = t[: max(0, limit - 3)] + "..."
    return t


def full_method_signature(declaring_type: str, method_name: str, partial_sig: str) -> str:
    """
    CodeQL rows use declaring_type + partial signature from getSignature()
    (e.g. 'readOcspResponseCacheServer()').
    """
    pt = (declaring_type or "").strip()
    ps = (partial_sig or "").strip()
    if not ps and method_name:
        ps = f"{method_name}()"
    if not pt:
        return ps
    if ps.startswith(pt + "."):
        return ps
    return f"{pt}.{ps}"


def split_qualified_type_and_method(full_sig: str) -> tuple[str, str]:
    """
    Split ``pkg.Class.method(java...)`` into (``pkg.Class``, ``method(java...)``).
    Must split only on the dot before the simple method name — not on dots inside params.
    """
    if "(" in full_sig:
        idx = full_sig.index("(")
        pre = full_sig[:idx]
        rest = full_sig[idx:]
    else:
        pre = full_sig
        rest = ""
    if "." in pre:
        qtype, simple = pre.rsplit(".", 1)
        return qtype, simple + rest
    return "", pre + rest


def method_node_id(declaring_type: str, method_name: str, partial_sig: str) -> str:
    full = full_method_signature(declaring_type, method_name, partial_sig)
    qtype, method_part = split_qualified_type_and_method(full)
    if qtype:
        return f"{qtype}#{method_part}"
    if "." in full:
        return f"{full}#{method_name or full.rsplit('.', 1)[-1]}"
    return f"{full}#{full}"


def method_sig_part_from_full(full_sig: str) -> str:
    """Strip declaring type prefix; keep 'method(params)' / '<clinit>()' / 'Type(args)'."""
    if "(" in full_sig:
        idx = full_sig.index("(")
        pre = full_sig[:idx]
        param_part = full_sig[idx:]
        simple = pre.rsplit(".", 1)[-1]
        return simple + param_part
    if "." in full_sig:
        return full_sig.rsplit(".", 1)[-1]
    return full_sig


def normalize_call_edge(row: dict[str, Any]) -> dict[str, Any]:
    """Map heterogeneous CodeQL / CSV column names to canonical fields."""

    def pick(keys: list[str]) -> str:
        for k in keys:
            if k in row and row[k] not in (None, ""):
                return str(row[k])
        return ""

    caller_type = pick(
        [
            "caller_type",
            "callerType",
            "caller_class",
            "callerClass",
            "col0",
        ]
    )
    caller_method = pick(
        [
            "caller_method",
            "callerMethod",
            "caller_name",
            "col1",
        ]
    )
    caller_signature = pick(
        [
            "caller_signature",
            "callerSignature",
            "caller_sig",
            "caller",
            "source",
            "source_signature",
            "col2",
        ]
    )

    callee_type = pick(
        [
            "callee_type",
            "calleeType",
            "callee_class",
            "calleeClass",
            "col3",
        ]
    )
    callee_method = pick(
        [
            "callee_method",
            "calleeMethod",
            "callee_name",
            "col4",
        ]
    )
    callee_signature = pick(
        [
            "callee_signature",
            "calleeSignature",
            "callee_sig",
            "callee",
            "target",
            "target_signature",
            "col5",
        ]
    )

    file_val = pick(
        [
            "file",
            "path",
            "call_file",
            "location_file",
            "col6",
        ]
    )
    line_raw = pick(
        [
            "line",
            "call_line",
            "start_line",
            "location_line",
            "col7",
        ]
    )
    try:
        line_val = int(line_raw) if line_raw != "" else 0
    except ValueError:
        line_val = 0

    if not callee_signature and callee_method:
        callee_signature = f"{callee_method}()"
    if not caller_signature and caller_method:
        caller_signature = f"{caller_method}()"

    full_caller = full_method_signature(caller_type, caller_method, caller_signature)
    full_callee = full_method_signature(callee_type, callee_method, callee_signature)

    if not full_caller or not full_callee:
        raise ValueError(
            "normalize_call_edge: missing caller or callee signature after mapping; "
            f"row keys={list(row.keys())}"
        )
    if not file_val and not line_raw:
        logger.debug("normalize_call_edge: missing file/line for row keys=%s", list(row.keys()))

    return {
        "caller_type": caller_type,
        "caller_method": caller_method,
        "caller_signature": full_caller,
        "callee_type": callee_type,
        "callee_method": callee_method,
        "callee_signature": full_callee,
        "file": file_val,
        "line": line_val,
    }


def _unwrap_rows(raw: Any) -> list[Any]:
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        for k in ("rows", "data", "edges", "results"):
            if k in raw and isinstance(raw[k], list):
                return raw[k]
        if all(isinstance(x, str) for x in raw.keys()) and raw:
            return [raw]
    return []


def load_call_edges_rows(path: Path) -> list[dict[str, Any]]:
    """Load call edges from JSON (several shapes) or CSV."""
    if not path.is_file():
        raise FileNotFoundError(f"call edges file not found: {path}")

    if path.suffix.lower() == ".json":
        raw = json.loads(path.read_text(encoding="utf-8"))
        rows = _unwrap_rows(raw)
        if not rows:
            return []
        first = rows[0]
        if isinstance(first, dict):
            logger.info("call_edges JSON first row keys: %s", list(first.keys()))
        out: list[dict[str, Any]] = []
        for r in rows:
            if isinstance(r, dict):
                out.append(normalize_call_edge(r))
        return out

    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.reader(f)
            grid = list(reader)
        if not grid:
            return []
        header = grid[0]
        logger.info("call_edges CSV header: %s", header)
        body = grid[1:]
        if header and header[0].strip().lower() == "col0":
            headers = [
                "caller_type",
                "caller_method",
                "caller_signature",
                "callee_type",
                "callee_method",
                "callee_signature",
                "file",
                "line",
            ]
            rows_dicts: list[dict[str, Any]] = []
            for raw in body:
                if not raw:
                    continue
                pad = raw + [""] * max(0, len(headers) - len(raw))
                rows_dicts.append({headers[i]: pad[i] for i in range(len(headers))})
            return [normalize_call_edge(r) for r in rows_dicts]
        rows_dicts = []
        for raw in body:
            if not raw:
                continue
            pad = raw + [""] * max(0, len(header) - len(raw))
            rows_dicts.append({header[i]: pad[i] for i in range(min(len(header), len(pad)))})
        return [normalize_call_edge(r) for r in rows_dicts]

    raise ValueError(f"Unsupported call edges format: {path}")


def build_call_graph_from_codeql_edges(
    call_edges_json: Path,
    output_dir: Path,
    case_id: str,
    downstream_name: str,
) -> dict[str, Any]:
    rows = load_call_edges_rows(call_edges_json)
    if not rows:
        raise ValueError(f"No call edges loaded from {call_edges_json}")

    output_dir.mkdir(parents=True, exist_ok=True)

    nodes: dict[str, dict[str, Any]] = {}
    edges_unique: dict[tuple[str, str, str, int], dict[str, Any]] = {}
    duplicate_edges_removed = 0
    raw_count = 0
    self_edges = 0
    external_edges = 0

    for norm in rows:
        raw_count += 1
        ct = norm["caller_type"]
        ctm = norm["caller_method"]
        cs = norm["caller_signature"]
        kt = norm["callee_type"]
        km = norm["callee_method"]
        ks = norm["callee_signature"]

        src_id = method_node_id(ct, ctm, method_sig_part_from_full(cs))
        tgt_id = method_node_id(kt, km, method_sig_part_from_full(ks))

        cf = norm["file"]
        cl = norm["line"]

        key = (src_id, tgt_id, cf, cl)
        if key in edges_unique:
            duplicate_edges_removed += 1
            continue

        if ct != kt:
            external_edges += 1
        if src_id == tgt_id:
            self_edges += 1

        edges_unique[key] = {
            "source": src_id,
            "target": tgt_id,
            "source_signature": cs,
            "target_signature": ks,
            "call_file": cf,
            "call_line": cl,
            "call_kind": "method_call",
            "source_query": "CallEdges.ql",
        }

        def touch(node_id: str, sig: str, dtype: str, method: str, file_: str, line_: int) -> None:
            if node_id not in nodes:
                nodes[node_id] = {
                    "id": node_id,
                    "type": "method",
                    "declaring_type": dtype,
                    "method": method,
                    "signature": sig,
                    "files": [],
                    "lines": [],
                }
            rec = nodes[node_id]
            if file_ and file_ not in rec["files"]:
                rec["files"].append(file_)
            if line_ and line_ not in rec["lines"]:
                rec["lines"].append(line_)

        touch(src_id, cs, ct, ctm, cf, cl)
        touch(tgt_id, ks, kt, km, cf, cl)

    edge_list = list(edges_unique.values())

    graph_obj = {
        "case_id": case_id,
        "downstream": downstream_name,
        "analysis_engine": "codeql",
        "graph_type": "method_call_graph",
        "nodes": sorted(nodes.values(), key=lambda x: x["id"]),
        "edges": edge_list,
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edge_list),
            "self_edges": self_edges,
            "external_edges": external_edges,
            "duplicate_edges_removed": duplicate_edges_removed,
            "raw_edge_rows": raw_count,
        },
    }

    (output_dir / "full_callgraph.json").write_text(
        json.dumps(graph_obj, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    csv_path = output_dir / "full_callgraph.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "source_id",
                "target_id",
                "source_signature",
                "target_signature",
                "call_file",
                "call_line",
            ]
        )
        for e in edge_list:
            w.writerow(
                [
                    e["source"],
                    e["target"],
                    e["source_signature"],
                    e["target_signature"],
                    e["call_file"],
                    e["call_line"],
                ]
            )

    dot_lines = ["digraph callgraph {"]
    for e in edge_list:
        ss = dot_escape_label(e["source_signature"], limit=400)
        ts = dot_escape_label(e["target_signature"], limit=400)
        lab = dot_escape_label(f"{e['call_file']}:{e['call_line']}", limit=120)
        dot_lines.append(f'  "{ss}" -> "{ts}" [label="{lab}"];')
    dot_lines.append("}")
    (output_dir / "full_callgraph.dot").write_text("\n".join(dot_lines), encoding="utf-8")

    summary_path = output_dir / "callgraph_summary.json"
    summary_obj = {
        "case_id": case_id,
        "downstream": downstream_name,
        "output_dir": str(output_dir.resolve()),
        "summary": graph_obj["summary"],
    }
    summary_path.write_text(json.dumps(summary_obj, ensure_ascii=False, indent=2), encoding="utf-8")

    return summary_obj


def convert_codeql_csv_to_callgraph(codeql_csv_path: Path, output_dir: Path, prefix: str = "downstream") -> Tuple[Path, Path]:
    """
    Backwards-compatible hook: build real edges from CodeQL CSV or sibling JSON.
    Writes {prefix}_callgraph.csv and {prefix}_callgraph.dot under output_dir.
    """
    json_path = codeql_csv_path.with_suffix(".json")
    src = json_path if json_path.is_file() else codeql_csv_path
    rows = load_call_edges_rows(src)
    if not rows:
        raise ValueError(f"No rows loaded from {src}")

    output_dir.mkdir(parents=True, exist_ok=True)
    csv_out = output_dir / f"{prefix}_callgraph.csv"
    dot_out = output_dir / f"{prefix}_callgraph.dot"

    dedup_edges: dict[tuple[str, str, str, int], dict[str, Any]] = {}
    for norm in rows:
        tup = (
            norm["caller_signature"],
            norm["callee_signature"],
            norm["file"],
            norm["line"],
        )
        if tup in dedup_edges:
            continue
        dedup_edges[tup] = norm

    with csv_out.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "source_signature",
                "target_signature",
                "call_file",
                "call_line",
            ]
        )
        for norm in dedup_edges.values():
            w.writerow([norm["caller_signature"], norm["callee_signature"], norm["file"], norm["line"]])

    dot_lines = [f"digraph {prefix} {{"]
    for norm in dedup_edges.values():
        ss = dot_escape_label(norm["caller_signature"], limit=400)
        ts = dot_escape_label(norm["callee_signature"], limit=400)
        lab = dot_escape_label(f"{norm['file']}:{norm['line']}", limit=120)
        dot_lines.append(f'  "{ss}" -> "{ts}" [label="{lab}"];')
    dot_lines.append("}")
    dot_out.write_text("\n".join(dot_lines), encoding="utf-8")
    return csv_out, dot_out
