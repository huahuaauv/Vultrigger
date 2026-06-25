"""Score and rank parameter-level reachability paths for downstream test-path selection."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


ELIGIBLE_STATUSES = frozenset({"parameter_confirmed_reachable", "parameter_candidate_reachable"})


def _norm(s: str) -> str:
    return s.replace("\\", "/").lower()


def _evidence_blob(path: dict[str, Any]) -> str:
    parts: list[str] = []
    c = path.get("carrier") or {}
    if isinstance(c, dict):
        for x in c.get("evidence") or []:
            parts.append(str(x))
    for x in path.get("evidence") or []:
        parts.append(str(x))
    return " ".join(parts)


def _parameter_flow_blob(pf: dict[str, Any]) -> str:
    nodes = pf.get("nodes") or []
    edges = pf.get("edges") or []
    exprs = " ".join(str(n.get("expr", "")) for n in nodes if isinstance(n, dict))
    evs = " ".join(str(e.get("evidence", "")) for e in edges if isinstance(e, dict))
    return f"{exprs} {evs}"


def _path_length(path: dict[str, Any]) -> int:
    mp = path.get("method_path") or []
    if isinstance(mp, list) and mp:
        return len(mp)
    return 1


def _same_method_entry_bridge(path: dict[str, Any]) -> bool:
    entry = path.get("entry") or {}
    bp = path.get("bridge_point") or {}
    es = str(entry.get("signature", "")).strip()
    bs = str(bp.get("signature", "")).strip()
    return bool(es and bs and es == bs)


def _parse_java_params(signature: str) -> list[str]:
    """Extract parameter type strings from 'Class.method(T1,T2)'."""
    m = re.search(r"\(([^)]*)\)\s*$", signature.strip())
    if not m:
        return []
    inner = m.group(1).strip()
    if not inner:
        return []
    return [p.strip() for p in inner.split(",")]


def _entry_param_types(entry: dict[str, Any]) -> list[str]:
    sig = str(entry.get("signature", ""))
    return _parse_java_params(sig)


def _entry_file_region(entry: dict[str, Any]) -> str:
    fp = _norm(str(entry.get("file", "")))
    if "src/test/java" in fp:
        return "test"
    if "src/main/java" in fp:
        return "main"
    return "other"


def _path_strings(path: dict[str, Any]) -> str:
    chunks: list[str] = []
    for k in ("entry", "bridge_point", "method_path", "carrier"):
        chunks.append(json.dumps(path.get(k), ensure_ascii=False, default=str))
    chunks.append(_parameter_flow_blob(path.get("parameter_flow") or {}))
    return _norm(" ".join(chunks))


def _hits_generated_or_target_classes(path: dict[str, Any]) -> bool:
    blob = _path_strings(path)
    return "target/classes" in blob or "/generated/" in blob or "\\generated\\" in blob or "generated-sources" in blob


def _hits_clinit_enum_factory(path: dict[str, Any]) -> bool:
    blob = _path_strings(path)
    if "<clinit>" in blob or "values(" in blob or "valueof(" in blob.lower():
        return True
    for step in path.get("method_path") or []:
        if not isinstance(step, dict):
            continue
        m = str(step.get("method", ""))
        if m in {"<clinit>", "values", "valueOf"}:
            return True
    return False


def _execute_traceable(evidence_blob: str) -> bool:
    return "execute argument linked via localcarrierflow in same method" in evidence_blob.lower()


def _sink_line(evidence_blob: str) -> str:
    for part in evidence_blob.split():
        if "sink=" in part.lower():
            return evidence_blob
    low = evidence_blob.lower()
    if "sink=seturi" in low:
        return "sink=setURI"
    if "sink=execute" in low:
        idx = low.index("sink=execute")
        return evidence_blob[idx : idx + 120]
    return evidence_blob


def score_carrier(carrier: dict[str, Any]) -> tuple[float, str]:
    st = str(carrier.get("status", "unknown")).lower()
    if st == "confirmed":
        return 35.0, "confirmed"
    if st == "strong_candidate":
        return 28.0, "strong_candidate"
    if st == "candidate":
        return 18.0, "candidate"
    return 0.0, "unknown"


def score_bridge(path: dict[str, Any], pf_blob: str, evidence_blob: str) -> tuple[float, bool, str]:
    """
    Returns (bridge_score, execute_request_traceable_for_bucket, bridge_kind_label).
    execute_request_traceable: sink is execute and LocalCarrierFlow linked.
    """
    e = evidence_blob.lower()
    pf = pf_blob.lower()
    traceable = _execute_traceable(evidence_blob)
    if "sink=seturi" in e:
        if "build" in e or ".build(" in pf:
            return 25.0, traceable, "setURI_build"
        return 23.0, traceable, "setURI"
    if "sink=execute" in e:
        has_new_get = "new httpget" in pf or "new httpget" in e
        has_new_post = "new httppost" in pf or "new httppost" in e
        has_tostring = "tostring" in pf or "tostring" in e
        if (has_new_get or has_new_post) and has_tostring:
            return 22.0, traceable, "http_ctor_tostring"
        if has_new_get or has_new_post:
            return 24.0, traceable, "http_ctor"
        if traceable:
            return 18.0, traceable, "execute_traceable"
        return 6.0, False, "execute_opaque"
    return 0.0, traceable, "other"


def score_local_flow(pf: dict[str, Any], evidence_blob: str) -> tuple[float, str]:
    blob = _parameter_flow_blob(pf).lower()
    ev = evidence_blob.lower()
    nodes = pf.get("nodes") or []
    edges = pf.get("edges") or []
    has_graph = bool(nodes) or bool(edges)

    has_uri = "new uri" in blob or "new_uri" in blob or ".build(" in blob
    has_url = "new url" in blob or "new_url" in blob
    has_builder_build = "builder.build" in blob or ".build(" in blob
    has_getpost = "new httpget" in blob or "new httppost" in blob or "seturi" in blob
    has_exec = "sink=execute" in ev or "execute argument linked" in ev
    has_seturi_sink = "sink=seturi" in ev

    sink_ok = has_exec or has_seturi_sink
    if (has_uri or has_url or has_builder_build) and has_getpost and sink_ok:
        return 20.0, "full_local_chain"
    if ((has_uri or has_url or has_getpost) and has_exec) or (has_uri and has_seturi_sink):
        return 12.0, "partial_local_chain"
    if has_graph:
        return 12.0, "partial_local_chain"
    return 5.0, "bridge_argument_only"


def score_entry(entry: dict[str, Any]) -> tuple[float, str]:
    total = 0.0
    reasons: list[str] = []
    ek = str(entry.get("entry_kind", ""))
    if ek == "public_method_with_input_params":
        total += 6.0
        reasons.append("public_entry")
    params = _entry_param_types(entry)
    uri_like = re.compile(
        r"^(java\.lang\.String|java\.net\.(URI|URL)|java\.io\.File|java\.nio\.file\.Path)(\[|$)",
        re.I,
    )
    if any(uri_like.match(p) for p in params):
        total += 4.0
        reasons.append("entry_param_uri_like")
    region = _entry_file_region(entry)
    if region == "main":
        total += 3.0
        reasons.append("entry_in_main")
    elif region == "test":
        total += 1.0
        reasons.append("entry_in_test")
    cap = min(total, 10.0)
    return cap, ",".join(reasons) if reasons else "entry_minimal"


def score_path_complexity(path: dict[str, Any]) -> tuple[float, str]:
    plen = _path_length(path)
    if _same_method_entry_bridge(path):
        return 10.0, "same_method"
    if plen <= 3:
        return 9.0, f"path_len_{plen}_le_3"
    if plen <= 5:
        return 7.0, f"path_len_{plen}_le_5"
    if plen <= 8:
        return 4.0, f"path_len_{plen}_le_8"
    return 0.0, f"path_len_{plen}"


def score_testability(path: dict[str, Any], evidence_blob: str, pf: dict[str, Any]) -> tuple[float, list[str]]:
    """Conservative partial scores; default 0 when uncertain."""
    score = 0.0
    notes: list[str] = []
    nodes = pf.get("nodes") or []
    if len(nodes) >= 4:
        score += 1.0
        notes.append("bridge_context_nodes")
    entry = path.get("entry") or {}
    if _entry_file_region(entry) == "test":
        score += 3.0
        notes.append("entry_test_source")
    el = evidence_blob.lower()
    blob = (_path_strings(path)).lower()
    heavy_cert = any(
        x in blob
        for x in (
            "trustmanager",
            "x509",
            "ssl",
            "certificate",
            "ocsp",
            "revocation",
            "checkservertrusted",
        )
    )
    if "sink=seturi" in el and "build" in el and not heavy_cert:
        score += 5.0
        notes.append("seturi_builder_sink")
    if str(entry.get("entry_kind", "")).lower() == "junit_test" and not heavy_cert:
        score += 3.0
        notes.append("junit_entry")
    sig = str(entry.get("signature", "")).lower()
    if "httpclient" in sig and _entry_file_region(entry) == "test":
        score += 3.0
        notes.append("httpclient_in_test_signature")
    return min(score, 15.0), notes


def score_penalties(
    path: dict[str, Any],
    status: str,
    carrier: dict[str, Any],
    evidence_blob: str,
) -> tuple[float, list[str]]:
    penalties: list[tuple[float, str]] = []
    el = evidence_blob.lower()
    st = str(carrier.get("status", "unknown")).lower()
    if st == "unknown":
        penalties.append((15.0, "carrier_unknown"))
    if status == "method_only_reachable":
        penalties.append((30.0, "method_only_reachable"))
    if "sink=execute" in el and not _execute_traceable(evidence_blob):
        penalties.append((12.0, "execute_request_opaque"))
    if _hits_generated_or_target_classes(path):
        penalties.append((20.0, "generated_or_target_classes"))
    if _hits_clinit_enum_factory(path):
        penalties.append((10.0, "clinit_or_enum_factory"))
    plen = _path_length(path)
    extra = max(0, plen - 3)
    if extra > 0:
        penalties.append((0.5 * extra, "path_depth"))
    blob = _path_strings(path).lower()
    if any(
        x in blob
        for x in (
            "ocsp",
            "revocation",
            "oauth",
            "jdbc",
            "datasource",
            "amazonaws",
            "kms",
        )
    ):
        penalties.append((10.0, "network_or_external_service"))
    total = sum(p for p, _ in penalties)
    return total, [f"{name}:{amt}" for amt, name in penalties]


def bridge_bucket(path: dict[str, Any], evidence_blob: str, pf_blob: str) -> str:
    e = evidence_blob.lower()
    pf = pf_blob.lower()
    if "sink=seturi" in e:
        return "setURI"
    if "sink=execute" in e and ("new httpget" in pf or "new httppost" in pf):
        return "http_constructor"
    if "sink=execute" in e and _execute_traceable(evidence_blob):
        return "execute_traceable"
    if "sink=execute" in e:
        return "execute_opaque"
    return "other"


def bridge_argument_summary(path: dict[str, Any], evidence_blob: str) -> str:
    carrier = path.get("carrier") or {}
    name = str(carrier.get("name", "")).strip()
    for line in carrier.get("evidence") or []:
        s = str(line)
        if "sink=" in s:
            return f"{name} @ {s}" if name else s
    return name or evidence_blob[:120]


def local_chain_summary(path: dict[str, Any], limit: int = 6) -> str:
    pf = path.get("parameter_flow") or {}
    nodes = pf.get("nodes") or []
    out: list[str] = []
    for n in nodes:
        if not isinstance(n, dict):
            continue
        ex = str(n.get("expr", "")).strip()
        if ex and ex not in out:
            out.append(ex)
        if len(out) >= limit:
            break
    return " -> ".join(out) if out else ""


@dataclass
class RankedPath:
    path_id: str
    path: dict[str, Any]
    score: float
    reachability_status: str
    score_breakdown: dict[str, float]
    reason: list[str]
    bridge_bucket: str
    bridge_argument: str
    local_chain_summary: str
    selected_for_test_generation: bool = False

    def to_ranking_row(self, rank: int) -> dict[str, Any]:
        return {
            "rank": rank,
            "path_id": self.path_id,
            "score": self.score,
            "reachability_status": self.reachability_status,
            "score_breakdown": {k: round(v, 2) for k, v in self.score_breakdown.items()},
            "reason": self.reason,
            "selected_for_test_generation": self.selected_for_test_generation,
        }


def rank_paths(reachable_paths_doc: dict[str, Any]) -> tuple[list[RankedPath], dict[str, Any]]:
    raw_paths = reachable_paths_doc.get("reachable_paths") or []
    all_ranked: list[RankedPath] = []
    for p in raw_paths:
        if not isinstance(p, dict):
            continue
        status = str(p.get("status", ""))
        if status not in ELIGIBLE_STATUSES:
            continue
        carrier = p.get("carrier") or {}
        if not isinstance(carrier, dict):
            carrier = {}
        pf = p.get("parameter_flow") or {}
        if not isinstance(pf, dict):
            pf = {}
        ev = _evidence_blob(p)
        pf_blob = _parameter_flow_blob(pf)

        c_score, c_lab = score_carrier(carrier)
        b_score, _b_tr, b_lab = score_bridge(p, pf_blob, ev)
        lf_score, lf_lab = score_local_flow(pf, ev)
        e_score, e_lab = score_entry(p.get("entry") or {})
        pc_score, pc_lab = score_path_complexity(p)
        t_score, t_notes = score_testability(p, ev, pf)

        pen_total, pen_detail = score_penalties(p, status, carrier, ev)

        raw_sum = c_score + b_score + lf_score + e_score + pc_score + t_score
        final = raw_sum - pen_total

        reasons: list[str] = [
            f"carrier:{c_lab}={c_score}",
            f"bridge:{b_lab}={b_score}",
            f"local_flow:{lf_lab}={lf_score}",
            f"entry:{e_lab}={e_score}",
            f"path:{pc_lab}={pc_score}",
            f"testability:{','.join(t_notes) or 'none'}={t_score}",
        ]
        if pen_detail:
            reasons.append("penalties:" + ";".join(pen_detail))

        bucket = bridge_bucket(p, ev, pf_blob)
        rp = RankedPath(
            path_id=str(p.get("path_id", "")),
            path=p,
            score=round(final, 2),
            reachability_status=status,
            score_breakdown={
                "carrier_score": c_score,
                "bridge_score": b_score,
                "local_flow_score": lf_score,
                "entry_score": e_score,
                "path_complexity_score": pc_score,
                "testability_score": t_score,
                "penalty_score": pen_total,
            },
            reason=reasons,
            bridge_bucket=bucket,
            bridge_argument=bridge_argument_summary(p, ev),
            local_chain_summary=local_chain_summary(p),
        )
        all_ranked.append(rp)

    all_ranked.sort(key=lambda x: x.score, reverse=True)
    summary = {
        "candidate_path_count": int(
            reachable_paths_doc.get("summary", {}).get("parameter_candidate_reachable_count", 0)
        ),
        "method_only_path_count": int(
            reachable_paths_doc.get("summary", {}).get("method_only_reachable_count", 0)
        ),
    }
    return all_ranked, summary


def select_paths_for_tests(
    ranked: list[RankedPath],
    selected_count: int,
) -> list[RankedPath]:
    """Greedy selection with per-bridge-method cap, per-entry-file cap, bridge-type diversity."""
    for rp in ranked:
        rp.selected_for_test_generation = False

    bucket_order = ["setURI", "http_constructor", "execute_traceable", "execute_opaque", "other"]
    by_bucket: dict[str, list[RankedPath]] = {b: [] for b in bucket_order}
    for rp in ranked:
        b = rp.bridge_bucket
        if b not in by_bucket:
            by_bucket[b] = []
        by_bucket[b].append(rp)
    for b in list(by_bucket.keys()):
        by_bucket[b].sort(key=lambda x: x.score, reverse=True)

    selected: list[RankedPath] = []
    used_bridge_methods: set[str] = set()
    file_counts: dict[str, int] = {}
    picked_ids: set[str] = set()

    def bridge_method_key(p: dict[str, Any]) -> str:
        bp = p.get("bridge_point") or {}
        return str(bp.get("signature", "")) or f"{bp.get('enclosing_type')}#{bp.get('enclosing_method')}@{bp.get('file')}:{bp.get('line')}"

    def entry_file_key(p: dict[str, Any]) -> str:
        return _norm(str((p.get("entry") or {}).get("file", "")))

    def can_take(rp: RankedPath) -> bool:
        p = rp.path
        bmk = bridge_method_key(p)
        if bmk in used_bridge_methods:
            return False
        ef = entry_file_key(p)
        if file_counts.get(ef, 0) >= 2:
            return False
        return True

    def take(rp: RankedPath) -> None:
        p = rp.path
        used_bridge_methods.add(bridge_method_key(p))
        ef = entry_file_key(p)
        file_counts[ef] = file_counts.get(ef, 0) + 1
        picked_ids.add(rp.path_id)
        rp.selected_for_test_generation = True
        selected.append(rp)

    # Round-robin across bridge buckets for diversity
    round_idx = 0
    max_list = max((len(by_bucket[b]) for b in bucket_order), default=0)
    max_rounds = max_list + len(ranked) + 5
    if selected_count <= 0:
        return selected

    while len(selected) < selected_count and round_idx < max_rounds:
        progressed = False
        for b in bucket_order:
            if len(selected) >= selected_count:
                break
            lst = by_bucket.get(b) or []
            if round_idx >= len(lst):
                continue
            cand = lst[round_idx]
            if cand.path_id in picked_ids:
                continue
            if can_take(cand):
                take(cand)
                progressed = True
        round_idx += 1
        if not progressed:
            break

    # Fill remaining slots by global score order
    if len(selected) < selected_count:
        for rp in ranked:
            if len(selected) >= selected_count:
                break
            if rp.path_id in picked_ids:
                continue
            if can_take(rp):
                take(rp)

    for rp in ranked:
        if rp not in selected:
            rp.selected_for_test_generation = False

    return selected


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def extract_test_hints(metadata: dict[str, Any], case_id: str, downstream: str) -> dict[str, Any]:
    case = metadata.get(case_id) or {}
    downs = case.get("downstreams") or []
    for d in downs:
        if not isinstance(d, dict):
            continue
        if str(d.get("name", "")) == downstream:
            apis = d.get("vulnerable_apis") or []
            api0 = apis[0] if apis and isinstance(apis[0], dict) else {}
            payload = str(d.get("poc_payload", "") or "")
            return {
                "preferred_payload": payload,
                "oracle_type": "host_mismatch_assertion",
                "avoid_real_network": True,
                "suggested_strategy": (
                    "Construct malformed URI/String and drive downstream code to HttpClient "
                    "request construction; assert extracted host differs from attacker-controlled authority."
                ),
                "vulnerable_api_signature": str(api0.get("signature", "")),
            }
    return {
        "preferred_payload": "",
        "oracle_type": "host_mismatch_assertion",
        "avoid_real_network": True,
        "suggested_strategy": "Use dataset metadata to supply payload and assertions.",
    }
