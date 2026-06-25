from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


def norm_file(p: str) -> str:
    return p.replace("\\", "/").strip()


def int_line(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return -1


def stable_node_id(file: str, line: int, method_sig: str, expr: str, kind: str) -> str:
    safe = re.sub(r"[^\w@.\-:+]+", "_", f"{norm_file(file)}:{line}:{method_sig}:{expr}:{kind}")[:220]
    return safe


def _load_list(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [x for x in raw if isinstance(x, dict)] if isinstance(raw, list) else []


def _load_obj(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    return raw if isinstance(raw, dict) else {}


def index_bridge_by_loc(rows: Iterable[dict[str, Any]]) -> dict[tuple[str, int], list[dict[str, Any]]]:
    out: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for r in rows:
        k = (norm_file(str(r.get("file", ""))), int_line(r.get("line")))
        if k[0] and k[1] >= 0:
            out.setdefault(k, []).append(r)
    return out


def index_local_flow(rows: Iterable[dict[str, Any]]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    out: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for r in rows:
        k = (norm_file(str(r.get("file", ""))), str(r.get("enclosing_method", "")))
        if k[0]:
            out.setdefault(k, []).append(r)
    return out


def index_callsite_by_loc(rows: Iterable[dict[str, Any]]) -> dict[tuple[str, int], list[dict[str, Any]]]:
    out: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for r in rows:
        k = (norm_file(str(r.get("file", ""))), int_line(r.get("line")))
        if k[0] and k[1] >= 0:
            out.setdefault(k, []).append(r)
    return out


def _expr_match(a: str, b: str) -> bool:
    a, b = a.strip(), b.strip()
    if not a or not b:
        return False
    return a == b or a in b or b in a


def _local_backward(
    seeds: set[str],
    file: str,
    method: str,
    local_index: dict[tuple[str, str], list[dict[str, Any]]],
    method_sig: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], set[str]]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen_nodes: set[str] = set()
    frontier = set(seeds)
    reached: set[str] = set(seeds)
    key = (norm_file(file), method)
    flows = local_index.get(key, [])
    max_rounds = 40
    for _ in range(max_rounds):
        if not frontier:
            break
        nxt: set[str] = set()
        for cur in list(frontier):
            for fl in flows:
                tgt = str(fl.get("target_expr", "")).strip()
                src = str(fl.get("source_expr", "")).strip()
                if not _expr_match(cur, tgt):
                    continue
                fk = str(fl.get("flow_kind", "unknown_local_flow"))
                conf = "confirmed" if fk in ("assignment", "constructor_argument", "set_uri_argument", "request_execute_argument") else "strong_candidate"
                sid = stable_node_id(file, int_line(fl.get("line")), method_sig, src, "expression")
                tid = stable_node_id(file, int_line(fl.get("line")), method_sig, tgt, "expression")
                for nid, expr, role in (
                    (sid, src, "intermediate"),
                    (tid, tgt, "intermediate"),
                ):
                    if nid not in seen_nodes:
                        seen_nodes.add(nid)
                        nodes.append(
                            {
                                "id": nid,
                                "kind": "expression",
                                "expr": expr,
                                "type_hint": "",
                                "method_signature": method_sig,
                                "declaring_type": str(fl.get("enclosing_type", "")),
                                "file": norm_file(file),
                                "line": int_line(fl.get("line")),
                                "role": role,
                            }
                        )
                eid = f"e-{sid}->{tid}-{fk}"
                edges.append(
                    {
                        "id": eid,
                        "source": sid,
                        "target": tid,
                        "kind": fk if fk != "unknown_local_flow" else "local_flow",
                        "evidence": str(fl.get("evidence", "")),
                        "confidence": conf,
                        "source_query": "LocalCarrierFlow.ql",
                    }
                )
                if src and src not in reached:
                    reached.add(src)
                    nxt.add(src)
        if not nxt:
            break
        frontier = nxt
    return nodes, edges, reached


def _simple_type_param_token(param_spec: str) -> str:
    """Last simple name from a Java parameter type spec, e.g. java.net.URI[] -> URI."""
    s = param_spec.strip()
    while s.endswith("[]"):
        s = s[:-2].strip()
    if "." in s:
        return s.rsplit(".", 1)[-1]
    return s


def _signature_is_parameterless(signature: str) -> bool:
    if "(" not in signature or ")" not in signature:
        return True
    inside = signature[signature.index("(") + 1 : signature.rindex(")")]
    return not inside.strip()


def _parse_java_params(signature: str) -> list[str]:
    """Return simple type-parameter tokens from `Type.method(T1 a, T2 b)` (names only, no FQNs)."""
    if "(" not in signature or ")" not in signature:
        return []
    inside = signature[signature.index("(") + 1 : signature.rindex(")")]
    if not inside.strip():
        return []
    names: list[str] = []
    for part in inside.split(","):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            names.append(_simple_type_param_token(tokens[-1]))
    return names


def _bridge_carrier_suitable(rows: list[dict[str, Any]]) -> bool:
    """True if bridge argument plausibly carries URI / URL / String / request (per phase-2 spec)."""
    if not rows:
        return False
    carrier_tokens = (
        "URI",
        "URL",
        "String",
        "HttpUriRequest",
        "HttpRequest",
        "HttpGet",
        "HttpPost",
        "HttpRequestBase",
        "HttpHost",
    )
    for r in rows:
        role = str(r.get("argument_role", ""))
        if role in ("uri_argument", "request_argument", "host_argument"):
            return True
        at = str(r.get("argument_type", ""))
        if any(t in at for t in carrier_tokens):
            return True
    return False


def _carrier_from_bridge_rows(rows: list[dict[str, Any]], reached: set[str]) -> dict[str, Any]:
    if not rows:
        return {
            "status": "unknown",
            "name": "",
            "type_hint": "",
            "source": "missing_bridge_argument_details",
            "evidence": [],
        }
    primary = sorted(rows, key=lambda r: (r.get("sink_method", "") != "setURI", r.get("argument_index", 0)))[0]
    arg = str(primary.get("argument_text", ""))
    at = str(primary.get("argument_type", ""))
    sk = str(primary.get("sink_method", ""))
    ev = [
        "Bridge argument resolved from CodeQL BridgeArgumentDetails",
        f"sink={sk} arg={arg} type={at} role={primary.get('argument_role', '')}",
    ]
    st = "candidate"
    if "URI" in at or "URL" in at or "String" in at:
        st = "confirmed"
    elif any(x in arg.lower() for x in ("uri", "url", "build", "tostring")):
        st = "strong_candidate"
    if sk == "execute" and any(_expr_match(arg, x) for x in reached):
        st = "confirmed"
        ev.append("execute argument linked via LocalCarrierFlow in same method")
    return {"status": st, "name": arg, "type_hint": at, "source": "bridge_argument", "evidence": ev}


def _parameter_reachability_status(
    entry: dict[str, Any],
    reached: set[str],
    cross_hops: int,
    bridge_resolved: bool,
    seed: str,
    edges: list[dict[str, Any]],
    b_rows: list[dict[str, Any]],
    method_edge_count: int,
    bridge_signature: str,
) -> tuple[str, list[str], list[str]]:
    reasons: list[str] = []
    lims: list[str] = []
    has_confirmed_edge = any(str(e.get("confidence", "")) == "confirmed" for e in edges)
    carrier_ok = _bridge_carrier_suitable(b_rows)

    if not bridge_resolved:
        return "method_only_reachable", ["Bridge argument not resolved from CodeQL BridgeArgumentDetails"], [
            "No parameter-level sink row for this bridge file:line"
        ]

    if not (seed or "").strip():
        return "method_only_reachable", ["Bridge row present but argument_text is empty"], ["Cannot seed reverse local flow"]

    if not edges and cross_hops == 0:
        return "method_only_reachable", ["No LocalCarrierFlow or CallSiteArgumentMapping edges in parameter graph"], [
            "CodeQL local_carrier_flow / callsite mapping missing for this path"
        ]

    generic_entry_tokens = frozenset(
        {
            "String",
            "Object",
            "Class",
            "Throwable",
            "Exception",
            "Integer",
            "Long",
            "Boolean",
            "Character",
            "Byte",
            "Short",
            "Float",
            "Double",
            "Void",
            "Iterable",
            "Collection",
            "List",
            "Map",
            "Set",
        }
    )
    entry_params = _parse_java_params(str(entry.get("signature", "")))
    entry_param_blob = str(entry.get("parameters", "")).lower()
    hit = False
    for p in entry_params:
        if not p or p in generic_entry_tokens:
            continue
        if any(_expr_match(p, r) for r in reached):
            hit = True
            reasons.append(f"Reached entry-related token `{p}` in propagated set")
    if not hit and entry_param_blob:
        blob_l = entry_param_blob.lower()
        min_blob_match = 6
        for r in reached:
            rl = (r or "").lower().strip()
            if len(rl) < min_blob_match or not rl.isidentifier():
                continue
            if rl in blob_l and rl not in ("string", "object", "boolean", "integer", "result"):
                hit = True
                reasons.append("Reached identifier matching entry.parameters hint")
                break

    arg_text = str(b_rows[0].get("argument_text", "")) if b_rows else ""
    if arg_text and (arg_text in ('""', "''") or arg_text in ("null", "true", "false")):
        return "parameter_unreachable", [f"Bridge argument looks like constant: {arg_text}"], ["Not user-controlled per static shape"]

    bridge_paramless = _signature_is_parameterless(bridge_signature)
    chain_ok = method_edge_count >= 2

    if hit and has_confirmed_edge and carrier_ok and cross_hops >= 1:
        reasons.append("Evidence chain includes at least one confirmed CodeQL-backed edge")
        reasons.append("Bridge argument type/role matches URI/String/request carrier profile")
        reasons.append("At least one cross-method argument_to_parameter hop links callee formals to caller actuals")
        return "parameter_confirmed_reachable", reasons, lims

    if hit and has_confirmed_edge and carrier_ok and bridge_paramless and chain_ok:
        reasons.append("Evidence chain includes at least one confirmed CodeQL-backed edge")
        reasons.append("Bridge argument type/role matches URI/String/request carrier profile")
        reasons.append(
            "Bridge callee is parameterless: confirmation uses entry-to-bridge method chain plus local carrier flow"
        )
        return "parameter_confirmed_reachable", reasons, lims

    if hit and has_confirmed_edge and carrier_ok:
        lims.append("Strict confirmation requires cross_hops>=1 or parameterless-bridge multi-hop chain")
        return "parameter_candidate_reachable", reasons, lims

    if hit:
        lims.append("Missing confirmed edge and/or carrier-type match for strict confirmation")
        return "parameter_candidate_reachable", reasons, lims

    if cross_hops > 0 or len(edges) > 0:
        if cross_hops > 0:
            reasons.append("Some cross-method argument_to_parameter mapping applied")
        else:
            reasons.append("Local propagation from bridge seed only")
        return "parameter_candidate_reachable", reasons, ["Did not match entry parameter names in reached set"]


@dataclass
class BuildStats:
    method_flow_path_count: int = 0
    parameter_graph_path_count: int = 0
    parameter_confirmed_reachable_count: int = 0
    parameter_candidate_reachable_count: int = 0
    method_only_reachable_count: int = 0
    parameter_unreachable_count: int = 0
    carrier_confirmed_count: int = 0
    carrier_strong_candidate_count: int = 0
    carrier_candidate_count: int = 0
    carrier_unknown_count: int = 0
    graph_nodes: int = 0
    graph_edges: int = 0
    bridge_matched: int = 0
    warnings: list[str] = field(default_factory=list)


def build_parameter_flow_outputs(
    *,
    metadata_path: Path,
    case_id: str,
    downstream: str,
    method_flow_path: Path,
    bridge_points_path: Path,
    codeql_json_dir: Path,
    parameter_flow_output_dir: Path,
    reachability_output_dir: Path,
    log_path: Path,
) -> BuildStats:
    meta = _load_obj(metadata_path)
    case = meta.get(case_id) or {}
    cve_id = str(case.get("cve_id", case_id))
    ds_entry = next(
        (d for d in (case.get("downstreams") or []) if str(d.get("name") or "") == downstream),
        None,
    )
    apis = (ds_entry or {}).get("vulnerable_apis") or case.get("vulnerable_apis") or []
    rec0 = apis[0] if isinstance(apis, list) and apis and isinstance(apis[0], dict) else {}
    poc_payload = ""
    if ds_entry and str(ds_entry.get("poc_payload") or "").strip():
        poc_payload = str(ds_entry.get("poc_payload"))
    vuln_api = {
        "class_name": str(rec0.get("class_name", "")),
        "method_name": str(rec0.get("method_name", "")),
        "signature": str(rec0.get("signature", "")),
        "payload": poc_payload,
    }

    mf = _load_obj(method_flow_path)
    paths = mf.get("paths") if isinstance(mf.get("paths"), list) else []

    bridge_rows = _load_list(codeql_json_dir / "bridge_argument_details.json")
    callsite_rows = _load_list(codeql_json_dir / "callsite_argument_mapping.json")
    local_rows = _load_list(codeql_json_dir / "local_carrier_flow.json")
    uri_rows = _load_list(codeql_json_dir / "uri_and_request_construction.json")

    br_idx = index_bridge_by_loc(bridge_rows)
    loc_idx = index_local_flow(local_rows)
    cs_idx = index_callsite_by_loc(callsite_rows)

    stats = BuildStats(method_flow_path_count=len(paths))
    all_path_payloads: list[dict[str, Any]] = []
    reachable_payload: list[dict[str, Any]] = []
    unreachable_payload: list[dict[str, Any]] = []

    log_lines: list[str] = [
        f"metadata={metadata_path}",
        f"method_flow={method_flow_path}",
        f"bridge_points={bridge_points_path}",
        f"codeql_json_dir={codeql_json_dir}",
        f"bridge_argument_details={len(bridge_rows)}",
        f"callsite_argument_mapping={len(callsite_rows)}",
        f"local_carrier_flow={len(local_rows)}",
        f"uri_and_request_construction={len(uri_rows)}",
    ]

    for i, path in enumerate(paths):
        if not isinstance(path, dict):
            continue
        pid = f"path-{i+1:04d}"
        bp = path.get("bridge_point") or {}
        fbp = norm_file(str(bp.get("file", "")))
        lbp = int_line(bp.get("line"))
        enc_m = str(bp.get("enclosing_method", ""))
        enc_sig = str(bp.get("signature", ""))
        b_rows = list(br_idx.get((fbp, lbp), []))
        if not b_rows:
            for (f2, l2), lst in br_idx.items():
                if f2 == fbp and abs(l2 - lbp) <= 1:
                    b_rows.extend(lst)
            b_rows = list({id(x): x for x in b_rows}.values())
        bridge_resolved = bool(b_rows)
        if bridge_resolved:
            stats.bridge_matched += 1

        seed = str(b_rows[0].get("argument_text", "")).strip() if b_rows else ""
        m_nodes = path.get("nodes") or []
        m_edges = path.get("edges") or []
        method_sig_bridge = str((m_nodes[-1] or {}).get("signature", enc_sig)) if m_nodes else enc_sig
        nodes_l, edges_l, reached = _local_backward({seed} if seed else set(), fbp, enc_m, loc_idx, method_sig_bridge)

        cross_hops = 0
        nodes = list(nodes_l)
        edges = list(edges_l)
        reached_set = set(reached)
        for j in range(len(m_edges) - 1, -1, -1):
            einfo = m_edges[j]
            cf = norm_file(str(einfo.get("call_file", "")))
            cl = int_line(einfo.get("call_line"))
            caller_node = m_nodes[j] if j < len(m_nodes) else {}
            callee_node = m_nodes[j + 1] if j + 1 < len(m_nodes) else {}
            callee_method = str(callee_node.get("method", ""))
            rows_cs = cs_idx.get((cf, cl), [])
            next_seeds: set[str] = set()
            for row in rows_cs:
                if str(row.get("callee_method", "")) != callee_method:
                    continue
                formal = str(row.get("formal_parameter_name", "")).strip()
                actual = str(row.get("actual_argument_text", "")).strip()
                if formal in reached_set or any(_expr_match(formal, r) for r in reached_set):
                    cross_hops += 1
                    ms_caller = str(caller_node.get("signature", ""))
                    ms_callee = str(callee_node.get("signature", ""))
                    sid = stable_node_id(cf, cl, ms_caller, actual, "actual_argument")
                    tid = stable_node_id(cf, cl, ms_callee, formal, "formal_parameter")
                    if sid not in {n["id"] for n in nodes}:
                        nodes.append(
                            {
                                "id": sid,
                                "kind": "actual_argument",
                                "expr": actual,
                                "type_hint": str(row.get("actual_argument_type", "")),
                                "method_signature": ms_caller,
                                "declaring_type": str(caller_node.get("declaring_type", "")),
                                "file": cf,
                                "line": cl,
                                "role": "carrier",
                            }
                        )
                    if tid not in {n["id"] for n in nodes}:
                        nodes.append(
                            {
                                "id": tid,
                                "kind": "formal_parameter",
                                "expr": formal,
                                "type_hint": str(row.get("formal_parameter_type", "")),
                                "method_signature": ms_callee,
                                "declaring_type": str(callee_node.get("declaring_type", "")),
                                "file": cf,
                                "line": cl,
                                "role": "intermediate",
                            }
                        )
                    edges.append(
                        {
                            "id": f"x-{sid}->{tid}-argmap",
                            "source": sid,
                            "target": tid,
                            "kind": "argument_to_parameter",
                            "evidence": str(row.get("call_text", "")),
                            "confidence": "confirmed",
                            "source_query": "CallSiteArgumentMapping.ql",
                        }
                    )
                    next_seeds.add(actual)
            if next_seeds:
                caller_sig = str(caller_node.get("signature", ""))
                caller_m = str(caller_node.get("method", ""))
                n2, e2, r2 = _local_backward(next_seeds, cf, caller_m, loc_idx, caller_sig)
                known = {n["id"] for n in nodes}
                for n in n2:
                    if n["id"] not in known:
                        nodes.append(n)
                        known.add(n["id"])
                edges.extend(e2)
                reached_set |= r2
        reached = reached_set

        carrier = _carrier_from_bridge_rows(b_rows, reached)
        cs = carrier["status"]
        if cs == "confirmed":
            stats.carrier_confirmed_count += 1
        elif cs == "strong_candidate":
            stats.carrier_strong_candidate_count += 1
        elif cs == "candidate":
            stats.carrier_candidate_count += 1
        else:
            stats.carrier_unknown_count += 1

        bridge_sig = str((m_nodes[-1] or {}).get("signature", enc_sig)) if m_nodes else enc_sig
        pr_status, reasons, lims = _parameter_reachability_status(
            path.get("entry") or {},
            reached,
            cross_hops,
            bridge_resolved,
            seed,
            edges,
            b_rows,
            len(m_edges),
            bridge_sig,
        )
        if pr_status == "parameter_confirmed_reachable":
            stats.parameter_confirmed_reachable_count += 1
        elif pr_status == "parameter_candidate_reachable":
            stats.parameter_candidate_reachable_count += 1
        elif pr_status == "method_only_reachable":
            stats.method_only_reachable_count += 1
        else:
            stats.parameter_unreachable_count += 1

        stats.parameter_graph_path_count += 1
        stats.graph_nodes += len(nodes)
        stats.graph_edges += len(edges)

        all_path_payloads.append(
            {
                "path_id": pid,
                "method_flow_path_id": pid,
                "bridge_point": bp,
                "carrier": carrier,
                "reverse_carrier_graph": {"nodes": nodes, "edges": edges},
                "parameter_reachability": {
                    "status": pr_status,
                    "reason": reasons,
                    "evidence_count": len(edges),
                },
            }
        )

        ev = list(carrier.get("evidence", [])) + reasons
        rp_entry = {
            "path_id": pid,
            "method_flow_path_id": pid,
            "status": pr_status,
            "entry": path.get("entry"),
            "bridge_point": bp,
            "carrier": carrier,
            "method_path": m_nodes,
            "parameter_flow": {"nodes": nodes, "edges": edges},
            "evidence": ev,
            "limitations": lims,
        }
        if pr_status == "parameter_unreachable":
            unreachable_payload.append(rp_entry)
        else:
            reachable_payload.append(rp_entry)

    parameter_flow_output_dir.mkdir(parents=True, exist_ok=True)
    reachability_output_dir.mkdir(parents=True, exist_ok=True)

    pgraph = {
        "case_id": case_id,
        "cve_id": cve_id,
        "downstream": downstream,
        "analysis_engine": "codeql",
        "graph_type": "reverse_parameter_propagation_graph",
        "vulnerable_api": vuln_api,
        "paths": all_path_payloads,
        "summary": {
            "method_flow_path_count": stats.method_flow_path_count,
            "parameter_graph_path_count": stats.parameter_graph_path_count,
            "parameter_confirmed_reachable_count": stats.parameter_confirmed_reachable_count,
            "parameter_candidate_reachable_count": stats.parameter_candidate_reachable_count,
            "method_only_reachable_count": stats.method_only_reachable_count,
            "parameter_unreachable_count": stats.parameter_unreachable_count,
            "carrier_confirmed_count": stats.carrier_confirmed_count,
            "carrier_strong_candidate_count": stats.carrier_strong_candidate_count,
            "carrier_candidate_count": stats.carrier_candidate_count,
            "carrier_unknown_count": stats.carrier_unknown_count,
        },
    }
    (parameter_flow_output_dir / "parameter_flow_graph.json").write_text(
        json.dumps(pgraph, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    rdoc = {
        "case_id": case_id,
        "cve_id": cve_id,
        "downstream": downstream,
        "analysis_engine": "codeql",
        "reachability_level": "parameter_level",
        "reachable_paths": reachable_payload,
        "unreachable_paths": unreachable_payload,
        "summary": {
            "method_flow_path_count": stats.method_flow_path_count,
            "parameter_confirmed_reachable_count": stats.parameter_confirmed_reachable_count,
            "parameter_candidate_reachable_count": stats.parameter_candidate_reachable_count,
            "method_only_reachable_count": stats.method_only_reachable_count,
            "parameter_unreachable_count": stats.parameter_unreachable_count,
        },
    }
    (reachability_output_dir / "parameter_reachable_paths.json").write_text(
        json.dumps(rdoc, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    summary_doc = {
        "case_id": case_id,
        "downstream": downstream,
        "analysis_engine": "codeql",
        "input_files": {
            "metadata": str(metadata_path),
            "method_flow": str(method_flow_path),
            "bridge_points": str(bridge_points_path),
            "codeql_json_dir": str(codeql_json_dir),
        },
        "query_counts": {
            "bridge_argument_details": len(bridge_rows),
            "callsite_argument_mapping": len(callsite_rows),
            "local_carrier_flow": len(local_rows),
            "uri_and_request_construction": len(uri_rows),
        },
        "results": {
            "method_flow_path_count": stats.method_flow_path_count,
            "parameter_confirmed_reachable_count": stats.parameter_confirmed_reachable_count,
            "parameter_candidate_reachable_count": stats.parameter_candidate_reachable_count,
            "method_only_reachable_count": stats.method_only_reachable_count,
            "parameter_unreachable_count": stats.parameter_unreachable_count,
            "carrier_confirmed_count": stats.carrier_confirmed_count,
            "carrier_strong_candidate_count": stats.carrier_strong_candidate_count,
            "carrier_candidate_count": stats.carrier_candidate_count,
            "carrier_unknown_count": stats.carrier_unknown_count,
            "parameter_graph_node_count": stats.graph_nodes,
            "parameter_graph_edge_count": stats.graph_edges,
            "bridge_argument_matched_paths": stats.bridge_matched,
        },
        "warnings": stats.warnings,
    }
    (reachability_output_dir / "parameter_reachability_summary.json").write_text(
        json.dumps(summary_doc, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    log_lines.extend(
        [
            f"method_flow_path_count={stats.method_flow_path_count}",
            f"bridge_matched_paths={stats.bridge_matched}",
            f"graph_nodes={stats.graph_nodes}",
            f"graph_edges={stats.graph_edges}",
            f"parameter_confirmed={stats.parameter_confirmed_reachable_count}",
            f"parameter_candidate={stats.parameter_candidate_reachable_count}",
            f"method_only={stats.method_only_reachable_count}",
            f"parameter_unreachable={stats.parameter_unreachable_count}",
        ]
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")

    return stats
