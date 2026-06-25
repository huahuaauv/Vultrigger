from __future__ import annotations

from pathlib import Path
from typing import Any

from src.third_phase.io import read_json
from src.third_phase.models import TestTask, default_oracle


def _resolve_project_root(work_root: Path, local_path: str) -> Path:
    p = Path(local_path)
    if p.is_absolute():
        return p.resolve()
    return (work_root / p).resolve()


def _index_parameter_flows_by_path_id(pfg: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in pfg.get("paths") or []:
        if not isinstance(row, dict):
            continue
        pid = str(row.get("path_id") or row.get("method_flow_path_id") or "")
        pf = row.get("reverse_carrier_graph") or row.get("parameter_flow")
        if isinstance(pf, dict) and pid:
            out[pid] = pf
    return out


def load_selected_test_tasks(
    metadata_path: Path,
    selected_test_paths_path: Path,
    parameter_flow_graph_path: Path | None = None,
    parameter_reachable_paths_path: Path | None = None,
) -> list[TestTask]:
    # dataset/metadata/dataset_match_info.json -> repo root is parents[2]
    work_root = metadata_path.resolve().parents[2]
    meta_all = read_json(metadata_path)
    sel_doc = read_json(selected_test_paths_path)
    selected = sel_doc.get("selected_paths") or []
    if not isinstance(selected, list) or not selected:
        raise ValueError(
            f"selected_test_paths.json has no selected_paths (or empty): {selected_test_paths_path}"
        )

    case_id = str(sel_doc.get("case_id") or "")
    downstream_name = str(sel_doc.get("downstream") or "")
    if not case_id or not downstream_name:
        raise ValueError("selected_test_paths.json missing case_id or downstream")

    case = meta_all.get(case_id) or {}
    cve_id = str(case.get("cve_id") or case_id)
    downs = case.get("downstreams") or []
    ds = next((d for d in downs if isinstance(d, dict) and str(d.get("name")) == downstream_name), None)
    if not ds:
        raise ValueError(f"downstream {downstream_name!r} not found in metadata for case {case_id}")

    project_root = _resolve_project_root(work_root, str(ds.get("local_path") or ""))
    if not project_root.is_dir():
        raise ValueError(f"downstream project_root is not a directory: {project_root}")

    payload = str(
        (ds.get("poc_payload") or case.get("poc", {}).get("payloads", [None])[0] or "")
    ).strip()
    if not payload:
        payload = "http://user@apache.org:80@google.com/"

    pf_by_id: dict[str, dict[str, Any]] = {}
    if parameter_flow_graph_path and parameter_flow_graph_path.is_file():
        pfg = read_json(parameter_flow_graph_path)
        if isinstance(pfg, dict):
            pf_by_id = _index_parameter_flows_by_path_id(pfg)

    reachable_by_id: dict[str, dict[str, Any]] = {}
    if parameter_reachable_paths_path and parameter_reachable_paths_path.is_file():
        pr = read_json(parameter_reachable_paths_path)
        for rp in pr.get("reachable_paths") or []:
            if not isinstance(rp, dict):
                continue
            pid = str(rp.get("path_id") or rp.get("method_flow_path_id") or "")
            pflow = rp.get("parameter_flow")
            if pid and isinstance(pflow, dict):
                reachable_by_id[pid] = pflow

    oracle = default_oracle()
    oracle["payload"] = payload

    tasks: list[TestTask] = []
    for row in selected:
        if not isinstance(row, dict):
            continue
        path_id = str(row.get("path_id") or "")
        if not path_id:
            continue
        entry = dict(row.get("entry") or {})
        bridge_point = dict(row.get("bridge_point") or {})
        carrier = dict(row.get("carrier") or {})
        method_path = list(row.get("method_path") or [])
        hints = dict(row.get("test_generation_hints") or {})
        if hints.get("preferred_payload"):
            row_payload = str(hints["preferred_payload"])
        else:
            row_payload = payload

        row_oracle = dict(oracle)
        row_oracle["payload"] = row_payload

        parameter_flow: dict[str, Any] = dict(row.get("parameter_flow") or {})
        if not parameter_flow.get("nodes") and not parameter_flow.get("edges"):
            parameter_flow = dict(pf_by_id.get(path_id) or reachable_by_id.get(path_id) or {})

        tasks.append(
            TestTask(
                case_id=case_id,
                cve_id=cve_id,
                downstream=downstream_name,
                project_root=str(project_root),
                path_id=path_id,
                rank=int(row.get("rank") or 0),
                score=float(row.get("score") or 0.0),
                reachability_status=str(row.get("reachability_status") or ""),
                entry=entry,
                bridge_point=bridge_point,
                carrier=carrier,
                method_path=method_path,
                parameter_flow=parameter_flow,
                payload=row_payload,
                oracle=row_oracle,
                test_generation_hints=hints,
                selected_path_raw=dict(row),
                selection_reason=list(row.get("selection_reason") or []),
            )
        )

    if not tasks:
        raise ValueError("No TestTask could be built from selected_paths rows")
    return tasks
