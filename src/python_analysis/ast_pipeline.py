from __future__ import annotations

import ast
import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "build",
    "dist",
    ".mypy_cache",
    ".pytest_cache",
    "node_modules",
    "site-packages",
}


@dataclass
class CallRecord:
    file: str
    line: int
    enclosing_signature: str
    callee_text: str
    qualified_callee: str
    args: list[str] = field(default_factory=list)
    keywords: dict[str, str] = field(default_factory=dict)


@dataclass
class FunctionRecord:
    id: str
    name: str
    qualname: str
    file: str
    line: int
    end_line: int
    parameters: list[str]
    calls: list[CallRecord] = field(default_factory=list)
    assignments: list[tuple[str, str, int]] = field(default_factory=list)
    returns: list[str] = field(default_factory=list)


def _safe_unparse(node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _module_name(root: Path, file_path: Path) -> str:
    rel = file_path.relative_to(root).with_suffix("")
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(p for p in parts if p)


def _iter_py_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        if p.name.startswith("."):
            continue
        yield p


def _normalize(s: str) -> str:
    return re.sub(r"[^a-z0-9_.]+", "", s.lower())


def _last_segments(s: str, n: int = 2) -> str:
    parts = [p for p in re.split(r"[.#:]", s) if p]
    return ".".join(parts[-n:]) if parts else s


def _expr_tokens(expr: str) -> set[str]:
    return {x for x in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", expr or "") if x not in {"None", "True", "False"}}


def _is_constant_expr(expr: str) -> bool:
    s = (expr or "").strip()
    if not s:
        return False
    if re.fullmatch(r"([rubfRUBF]*(['\"]).*\2|\d+(\.\d+)?)", s):
        return True
    if s in {"None", "True", "False"}:
        return True
    return False


def _alias_imports(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                head = a.name.split(".")[0]
                aliases[a.asname or head] = a.name
        elif isinstance(node, ast.ImportFrom):
            mod = "." * int(node.level or 0) + (node.module or "")
            for a in node.names:
                if a.name == "*":
                    continue
                aliases[a.asname or a.name] = f"{mod}.{a.name}".strip(".")
    return aliases


def _qualify_expr(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _qualify_expr(node.value, aliases)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _qualify_expr(node.func, aliases)
    return _safe_unparse(node)


class _FunctionCollector(ast.NodeVisitor):
    def __init__(self, root: Path, file_path: Path, tree: ast.AST) -> None:
        self.root = root
        self.file_path = file_path
        self.rel_file = file_path.relative_to(root).as_posix()
        self.module = _module_name(root, file_path)
        self.aliases = _alias_imports(tree)
        self.stack: list[str] = []
        self.functions: list[FunctionRecord] = []
        self.current: FunctionRecord | None = None

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qual = ".".join([self.module, *self.stack, node.name]).strip(".")
        params = [a.arg for a in list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)]
        if node.args.vararg:
            params.append(node.args.vararg.arg)
        if node.args.kwarg:
            params.append(node.args.kwarg.arg)
        rec = FunctionRecord(
            id=qual,
            name=node.name,
            qualname=qual,
            file=self.rel_file,
            line=int(getattr(node, "lineno", 0) or 0),
            end_line=int(getattr(node, "end_lineno", getattr(node, "lineno", 0)) or 0),
            parameters=params,
        )
        parent_current = self.current
        self.current = rec
        self.stack.append(node.name)
        for stmt in node.body:
            self.visit(stmt)
        self.stack.pop()
        self.current = parent_current
        self.functions.append(rec)

    def visit_Call(self, node: ast.Call) -> Any:
        if self.current is not None:
            self.current.calls.append(
                CallRecord(
                    file=self.rel_file,
                    line=int(getattr(node, "lineno", 0) or 0),
                    enclosing_signature=self.current.qualname,
                    callee_text=_safe_unparse(node.func),
                    qualified_callee=_qualify_expr(node.func, self.aliases),
                    args=[_safe_unparse(a) for a in node.args],
                    keywords={kw.arg or "**": _safe_unparse(kw.value) for kw in node.keywords},
                )
            )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> Any:
        if self.current is not None:
            src = _safe_unparse(node.value)
            for t in node.targets:
                self.current.assignments.append((_safe_unparse(t), src, int(getattr(node, "lineno", 0) or 0)))
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if self.current is not None:
            self.current.assignments.append((_safe_unparse(node.target), _safe_unparse(node.value), int(getattr(node, "lineno", 0) or 0)))
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> Any:
        if self.current is not None:
            self.current.returns.append(_safe_unparse(node.value))
        self.generic_visit(node)


def _collect_functions(project_root: Path) -> tuple[list[FunctionRecord], list[dict[str, Any]]]:
    funcs: list[FunctionRecord] = []
    parse_errors: list[dict[str, Any]] = []
    for py in _iter_py_files(project_root):
        try:
            text = py.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            text = py.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(text, filename=str(py))
        except SyntaxError as exc:
            parse_errors.append({"file": py.relative_to(project_root).as_posix(), "error": str(exc)})
            continue
        collector = _FunctionCollector(project_root, py, tree)
        collector.visit(tree)
        funcs.extend(collector.functions)
    return funcs, parse_errors


def _candidate_api_hints(case_doc: dict[str, Any], ds_doc: dict[str, Any]) -> list[str]:
    hints: list[str] = []
    for key in ("bridge_api_canonical_names",):
        for v in case_doc.get(key) or []:
            if str(v).strip() not in hints:
                hints.append(str(v).strip())
    for src in (case_doc.get("vulnerable_apis") or [], ds_doc.get("vulnerable_apis") or []):
        if not isinstance(src, dict):
            continue
        for key in ("signature", "class_name", "method_name"):
            v = str(src.get(key) or "").strip()
            if v and v not in hints:
                hints.append(v)
    for v in ds_doc.get("bridge_hints") or []:
        s = str(v).strip()
        if s and s not in hints:
            hints.append(s)
    pkg = ds_doc.get("dependency_hint") or {}
    for key in ("package", "artifact_id", "name"):
        v = str(pkg.get(key) or "").strip()
        if v and v not in hints:
            hints.append(v)
    return [h for h in hints if h]


def _call_matches(call: CallRecord, hints: list[str]) -> tuple[bool, str]:
    q = _normalize(call.qualified_callee or call.callee_text)
    text = _normalize(call.callee_text)
    for hint in hints:
        h = _normalize(hint)
        if not h:
            continue
        short = _normalize(_last_segments(hint, 2))
        one = _normalize(_last_segments(hint, 1))
        if h and (q.endswith(h) or h.endswith(q) or h in q):
            return True, hint
        if short and (q.endswith(short) or text.endswith(short)):
            return True, hint
        if one and len(one) >= 4 and (q.endswith("." + one) or q == one):
            return True, hint
    return False, ""


def _build_internal_edges(funcs: list[FunctionRecord]) -> tuple[list[dict[str, Any]], dict[str, FunctionRecord], dict[str, list[str]]]:
    by_id = {f.id: f for f in funcs}
    by_short: dict[str, list[str]] = defaultdict(list)
    for f in funcs:
        by_short[f.name].append(f.id)
        by_short[f.qualname.split(".")[-1]].append(f.id)
    edges: list[dict[str, Any]] = []
    reverse: dict[str, list[str]] = defaultdict(list)
    for f in funcs:
        for c in f.calls:
            target = ""
            cname = (c.qualified_callee or c.callee_text).split(".")[-1]
            candidates = by_short.get(cname) or []
            if len(candidates) == 1:
                target = candidates[0]
            elif candidates:
                # Prefer same file/module when ambiguous.
                same_file = [x for x in candidates if by_id[x].file == f.file]
                target = same_file[0] if same_file else candidates[0]
            if target:
                edges.append({"source": f.id, "target": target, "line": c.line, "callee": c.qualified_callee})
                reverse[target].append(f.id)
    return edges, by_id, reverse


def _reverse_paths(bridge_func: str, by_id: dict[str, FunctionRecord], reverse: dict[str, list[str]], max_depth: int = 6) -> list[list[str]]:
    paths: list[list[str]] = []
    q: deque[list[str]] = deque([[bridge_func]])
    seen: set[tuple[str, ...]] = set()
    while q and len(paths) < 30:
        cur = q.popleft()
        key = tuple(cur)
        if key in seen:
            continue
        seen.add(key)
        head = cur[0]
        callers = reverse.get(head) or []
        if not callers or len(cur) >= max_depth:
            paths.append(list(reversed(cur)))
            continue
        for caller in callers[:12]:
            if caller in cur:
                continue
            q.appendleft([caller, *cur])
    return paths or [[bridge_func]]


def _carrier_for_call(func: FunctionRecord, call: CallRecord) -> tuple[dict[str, Any], dict[str, Any], str, list[str]]:
    arg = call.args[0] if call.args else ""
    if not arg and call.keywords:
        arg = next(iter(call.keywords.values()))
    if not arg:
        return ({"status": "carrier_unknown", "name": "", "source": "no_call_argument", "evidence": []}, {"nodes": [], "edges": []}, "method_only_reachable", ["Bridge call has no explicit argument"])
    tokens = _expr_tokens(arg)
    params = set(func.parameters)
    assign_edges: list[dict[str, Any]] = []
    nodes: dict[str, dict[str, Any]] = {}

    def add_node(name: str, role: str) -> str:
        node_id = f"expr:{name}"
        nodes[node_id] = {"id": node_id, "label": name, "role": role}
        return node_id

    carrier_id = add_node(arg, "carrier")
    reached_params = set(tokens & params)
    for target, src, line in func.assignments:
        tks = _expr_tokens(target)
        sks = _expr_tokens(src)
        if tokens & tks or tokens & sks:
            sid = add_node(src, "source_expr")
            tid = add_node(target, "target_expr")
            assign_edges.append({"source": sid, "target": tid, "line": line, "kind": "assignment"})
            reached_params.update(sks & params)
            reached_params.update(tks & params)
    if _is_constant_expr(arg):
        status = "carrier_constant"
        reach = "parameter_unreachable"
        evidence = [f"Bridge argument is constant: {arg}"]
    elif reached_params:
        status = "carrier_confirmed"
        reach = "parameter_confirmed_reachable"
        evidence = ["Bridge carrier is source-traceable to function parameter(s): " + ", ".join(sorted(reached_params))]
    elif tokens:
        status = "carrier_candidate"
        reach = "parameter_candidate_reachable"
        evidence = ["Bridge carrier is non-constant but source relation to entry parameter is approximate"]
    else:
        status = "carrier_unknown"
        reach = "method_only_reachable"
        evidence = ["Could not extract carrier tokens from bridge argument"]
    graph = {"nodes": list(nodes.values()) or [{"id": carrier_id, "label": arg, "role": "carrier"}], "edges": assign_edges}
    return ({"status": status, "name": arg, "source": "python_ast_call_argument", "evidence": evidence}, graph, reach, evidence)


def _score_path(status: str, path_len: int, carrier_status: str) -> float:
    base = {
        "parameter_confirmed_reachable": 100.0,
        "parameter_candidate_reachable": 75.0,
        "method_only_reachable": 45.0,
        "parameter_unreachable": 0.0,
    }.get(status, 20.0)
    if carrier_status == "carrier_confirmed":
        base += 10.0
    elif carrier_status == "carrier_candidate":
        base += 4.0
    return max(0.0, base - max(0, path_len - 1) * 2.0)


def _method_row(f: FunctionRecord) -> dict[str, Any]:
    return {
        "id": f.id,
        "name": f.name,
        "signature": f.qualname,
        "file": f.file,
        "line": f.line,
        "end_line": f.end_line,
        "parameters": f.parameters,
    }


def run_python_analysis(
    *,
    metadata_path: Path,
    case_id: str,
    downstream: str,
    output_root: Path,
    selected_count: int = 3,
) -> dict[str, Any]:
    meta = json.loads(metadata_path.read_text(encoding="utf-8"))
    case_doc = meta.get(case_id) or {}
    ds_doc = next((d for d in case_doc.get("downstreams") or [] if isinstance(d, dict) and d.get("name") == downstream), None)
    if not ds_doc:
        raise ValueError(f"downstream not found in metadata: {case_id}/{downstream}")
    work_root = metadata_path.resolve().parents[2]
    project_root = Path(ds_doc.get("local_path") or "")
    if not project_root.is_absolute():
        project_root = (work_root / project_root).resolve()
    if not project_root.is_dir():
        raise ValueError(f"python downstream project_root not found: {project_root}")

    funcs, parse_errors = _collect_functions(project_root)
    edges, by_id, reverse = _build_internal_edges(funcs)
    hints = _candidate_api_hints(case_doc, ds_doc)

    bridges: list[dict[str, Any]] = []
    path_rows: list[dict[str, Any]] = []
    path_idx = 0
    for f in funcs:
        for call in f.calls:
            matched, hint = _call_matches(call, hints)
            if not matched:
                continue
            bridge_id = f"py-bridge-{len(bridges)+1:04d}"
            bridge = {
                "bridge_id": bridge_id,
                "language": "python",
                "file": call.file,
                "line": call.line,
                "enclosing_type": "",
                "enclosing_method": f.name,
                "enclosing_signature": f.qualname,
                "callee_signature": call.qualified_callee or call.callee_text,
                "callee_method": (call.qualified_callee or call.callee_text).split(".")[-1],
                "argument": call.args[0] if call.args else "",
                "argument_index": 0 if call.args else None,
                "matched_hint": hint,
                "source_query": "python_ast_frontend",
                "confidence": "candidate",
            }
            bridges.append(bridge)
            carrier, pflow, status, evidence = _carrier_for_call(f, call)
            for raw_path in _reverse_paths(f.id, by_id, reverse):
                path_idx += 1
                methods = [_method_row(by_id[x]) for x in raw_path if x in by_id]
                entry = methods[0] if methods else _method_row(f)
                score = _score_path(status, len(methods), str(carrier.get("status") or ""))
                path_rows.append(
                    {
                        "path_id": f"py-path-{path_idx:04d}",
                        "method_flow_path_id": f"py-path-{path_idx:04d}",
                        "language": "python",
                        "rank": 0,
                        "score": score,
                        "reachability_status": status,
                        "entry": entry,
                        "bridge_point": bridge,
                        "carrier": carrier,
                        "method_path": methods,
                        "parameter_flow": pflow,
                        "selection_reason": [
                            "Python AST candidate path",
                            "VulBridge matched by vulnerable API/import/call hint",
                            *evidence,
                        ],
                        "test_generation_hints": {
                            "framework": "pytest_or_unittest",
                            "preferred_payload": (ds_doc.get("poc_payload") or ""),
                            "python_entry_signature": entry.get("signature"),
                            "python_bridge_call": bridge.get("callee_signature"),
                            "direct_library_invocation_prohibited": True,
                            "validation_notes": "Runtime triggerability must be confirmed by pytest/unittest plus probe evidence.",
                        },
                    }
                )

    path_rows.sort(key=lambda r: float(r.get("score") or 0.0), reverse=True)
    for i, row in enumerate(path_rows, start=1):
        row["rank"] = i
    selected = path_rows[: max(0, selected_count)]

    bridge_dir = output_root / "outputs" / "bridge_points" / case_id / downstream
    call_dir = output_root / "outputs" / "call_graphs" / case_id / downstream
    param_dir = output_root / "outputs" / "parameter_flows" / case_id / downstream
    reach_dir = output_root / "outputs" / "reachability" / case_id / downstream
    selected_dir = output_root / "outputs" / "selected_paths" / case_id / downstream
    py_dir = output_root / "outputs" / "python_analysis" / case_id / downstream
    for d in (bridge_dir, call_dir, param_dir, reach_dir, selected_dir, py_dir):
        d.mkdir(parents=True, exist_ok=True)

    bridge_doc = {
        "case_id": case_id,
        "downstream": downstream,
        "language": "python",
        "analysis_engine": "python_ast",
        "bridge_points": bridges,
        "summary": {"total_bridge_points": len(bridges), "parse_errors": len(parse_errors)},
    }
    call_doc = {
        "case_id": case_id,
        "downstream": downstream,
        "language": "python",
        "graph_type": "python_ast_call_graph",
        "nodes": [_method_row(f) for f in funcs],
        "edges": edges,
        "parse_errors": parse_errors,
        "summary": {"node_count": len(funcs), "edge_count": len(edges)},
    }
    param_doc = {
        "case_id": case_id,
        "downstream": downstream,
        "language": "python",
        "graph_type": "python_ast_parameter_propagation_graph",
        "paths": [
            {
                "path_id": r["path_id"],
                "method_flow_path_id": r["method_flow_path_id"],
                "carrier": r["carrier"],
                "reverse_carrier_graph": r["parameter_flow"],
                "reachability_status": r["reachability_status"],
            }
            for r in path_rows
        ],
        "summary": _status_summary(path_rows),
    }
    reach_doc = {
        "case_id": case_id,
        "downstream": downstream,
        "language": "python",
        "analysis_engine": "python_ast",
        "reachable_paths": [r for r in path_rows if r.get("reachability_status") != "parameter_unreachable"],
        "unreachable_paths": [r for r in path_rows if r.get("reachability_status") == "parameter_unreachable"],
        "summary": _status_summary(path_rows),
    }
    selected_doc = {
        "case_id": case_id,
        "downstream": downstream,
        "language": "python",
        "selected_paths": selected,
        "summary": {
            "ranked_path_count": len(path_rows),
            "selected_path_count": len(selected),
            **_status_summary(selected),
        },
    }
    analysis_summary = {
        "case_id": case_id,
        "downstream": downstream,
        "language": "python",
        "analysis_engine": "python_ast",
        "project_root": str(project_root),
        "api_hints": hints,
        "files_parsed": len({f.file for f in funcs}),
        "function_count": len(funcs),
        "call_edge_count": len(edges),
        "bridge_point_count": len(bridges),
        "ranked_path_count": len(path_rows),
        "selected_path_count": len(selected),
        "parse_errors": parse_errors,
        "outputs": {
            "bridge_points": str(bridge_dir / "bridge_points.json"),
            "call_graph": str(call_dir / "full_callgraph.json"),
            "parameter_flow_graph": str(param_dir / "parameter_flow_graph.json"),
            "parameter_reachable_paths": str(reach_dir / "parameter_reachable_paths.json"),
            "selected_test_paths": str(selected_dir / "selected_test_paths.json"),
        },
    }

    (bridge_dir / "bridge_points.json").write_text(json.dumps(bridge_doc, ensure_ascii=False, indent=2), encoding="utf-8")
    (call_dir / "full_callgraph.json").write_text(json.dumps(call_doc, ensure_ascii=False, indent=2), encoding="utf-8")
    (param_dir / "parameter_flow_graph.json").write_text(json.dumps(param_doc, ensure_ascii=False, indent=2), encoding="utf-8")
    (reach_dir / "parameter_reachable_paths.json").write_text(json.dumps(reach_doc, ensure_ascii=False, indent=2), encoding="utf-8")
    (reach_dir / "parameter_reachability_summary.json").write_text(json.dumps(analysis_summary, ensure_ascii=False, indent=2), encoding="utf-8")
    (selected_dir / "selected_test_paths.json").write_text(json.dumps(selected_doc, ensure_ascii=False, indent=2), encoding="utf-8")
    (selected_dir / "path_ranking_report.json").write_text(json.dumps({"paths": selected, "summary": selected_doc["summary"]}, ensure_ascii=False, indent=2), encoding="utf-8")
    (py_dir / "python_analysis_summary.json").write_text(json.dumps(analysis_summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return analysis_summary


def _status_summary(rows: list[dict[str, Any]]) -> dict[str, int]:
    statuses = [str(r.get("reachability_status") or "") for r in rows]
    return {
        "method_flow_path_count": len(rows),
        "parameter_confirmed_reachable_count": statuses.count("parameter_confirmed_reachable"),
        "parameter_candidate_reachable_count": statuses.count("parameter_candidate_reachable"),
        "method_only_reachable_count": statuses.count("method_only_reachable"),
        "parameter_unreachable_count": statuses.count("parameter_unreachable"),
    }
