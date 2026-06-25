#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Run the full vulbridge experiment pipeline (phase 1–3) over every case under dataset/raw.

Phase 1 — static / flow: CodeQL DB + queries + bridge points + call graph + method_flow (.dot flowcharts).
Phase 2 — reachability: parameter CodeQL (optional) + parameter flow graph + path ranking + selected_test_paths.json.
Phase 3 — tests: third_phase orchestrator (LLM generation + verification, or smoke-only).

Metadata is synthesized from each ``dataset/raw/<CVE>/case_meta.json`` plus downstream folder names,
and written to ``outputs/full_dataset_run/generated_dataset_match_info.json`` so ``task_adapter`` resolves
``project_root`` as ``metadata.parents[2]`` (same layout as ``outputs/.../file.json``).

Prerequisites: CodeQL on PATH, Java/Maven for downstream builds, optional LLM config for phase 3.

本脚本为仓库内 **主控实验入口**：请通过本程序串联运行各阶段，便于统一日志、元数据与进度展示。
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, TypeVar

try:
    from tqdm import tqdm
except ImportError:  # pragma: no cover
    tqdm = None  # type: ignore[misc, assignment]

T = TypeVar("T")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MAIN_DRIVER_TITLE = "VulBridge 全流程实验主控 (dataset/raw → CodeQL → 可达性 → 单测)"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

DEFAULT_MAVEN = (
    "mvn -DskipTests -Dspotbugs.skip=true -Dcheckstyle.skip=true -Dlicense.skip=true "
    "-Dmaven.javadoc.skip=true -Djacoco.skip=true -Dmaven.wagon.http.ssl.insecure=true "
    "-Dmaven.wagon.http.ssl.allowall=true clean test-compile"
)


def _progress_bar(
    iterable: Iterable[T],
    *,
    total: int,
    desc: str,
    disable: bool,
) -> Iterable[T]:
    if disable or tqdm is None:
        return iterable
    return tqdm(
        iterable,
        total=total,
        desc=desc,
        unit="下游",
        dynamic_ncols=True,
        bar_format="{desc}: {percentage:3.0f}%|{bar}| {n}/{total} [{elapsed}<{remaining}] {postfix}",
    )


def _print_banner(dataset_raw: Path, pairs_n: int, phases: str) -> None:
    line = "=" * 72
    print(line)
    print(MAIN_DRIVER_TITLE)
    print(line)
    print(f"  项目根:    {PROJECT_ROOT}")
    print(f"  数据根:    {dataset_raw}")
    print(f"  下游对数:  {pairs_n}")
    print(f"  执行阶段:  {phases}")
    print(line)


def run_main_experiment(argv: list[str] | None = None) -> int:
    """对外主入口：与 ``main()`` 相同，便于其它模块 ``from ... import run_main_experiment``。"""
    if argv is not None:
        sys.argv = [sys.argv[0]] + argv
    return main()


def _parse_maven_coordinate(coord: str) -> tuple[str, str, str]:
    """Return (group_id, artifact_id, version_hint) from a coordinate string."""
    parts = [p.strip() for p in (coord or "").split(":") if p.strip()]
    if len(parts) >= 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], parts[1], ""
    return "", "", ""


def _api_to_vulnerable_record(api: str) -> dict[str, Any]:
    """Map a case_meta candidate_trigger_apis entry to dataset_match_info vulnerable_apis shape."""
    api = (api or "").strip()
    if not api:
        return {
            "class_name": "",
            "method_name": "",
            "signature": "",
            "parameter_index": 0,
            "trigger_condition": "unspecified",
        }
    if "(" in api:
        head, _, rest = api.partition("(")
        params = "(" + rest
        if "." in head:
            cls, _, meth = head.rpartition(".")
            sig = f"{cls}.{meth}{params}"
            return {
                "class_name": cls,
                "method_name": meth,
                "signature": sig,
                "parameter_index": 0,
                "trigger_condition": "from case_meta candidate_trigger_apis",
            }
        return {
            "class_name": "",
            "method_name": head,
            "signature": api,
            "parameter_index": 0,
            "trigger_condition": "from case_meta candidate_trigger_apis",
        }
    if "." in api:
        cls, _, meth = api.rpartition(".")
        return {
            "class_name": cls,
            "method_name": meth,
            "signature": f"{cls}.{meth}(...)",
            "parameter_index": 0,
            "trigger_condition": "from case_meta candidate_trigger_apis",
        }
    return {
        "class_name": "",
        "method_name": api,
        "signature": api,
        "parameter_index": 0,
        "trigger_condition": "from case_meta candidate_trigger_apis",
    }


def _bridge_hints_from_apis(apis: list[str]) -> list[str]:
    out: list[str] = []
    for a in apis or []:
        s = str(a).strip()
        if s and s not in out:
            out.append(s)
    return out[:12]


def _load_upstream_bridge_apis(case_dir: Path) -> tuple[list[str], list[str]]:
    """
    Read ``poc/upstream_bridge_apis.json`` (per CVE case).
    Returns (hint_strings for call-graph matching, canonical_name list for metadata).
    """
    path = case_dir / "poc" / "upstream_bridge_apis.json"
    if not path.is_file():
        return [], []
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return [], []
    if not isinstance(doc, dict):
        return [], []
    hints: list[str] = []
    canonical: list[str] = []
    for row in doc.get("bridge_apis") or []:
        if not isinstance(row, dict):
            continue
        cn = str(row.get("canonical_name") or "").strip()
        if cn:
            canonical.append(cn)
            java_sig = cn.replace("#", ".", 1) if "#" in cn else cn
            for s in (java_sig, cn):
                if s and s not in hints:
                    hints.append(s)
        sl = str(row.get("short_label") or "").strip()
        if sl and sl not in hints:
            hints.append(sl)
    return hints, canonical


def _merge_bridge_hint_lists(*groups: list[str], cap: int = 24) -> list[str]:
    out: list[str] = []
    for g in groups:
        for x in g or []:
            s = str(x).strip()
            if s and s not in out:
                out.append(s)
            if len(out) >= cap:
                return out
    return out


def _vulnerable_record_for_case(apis: list[str], canonical_names: list[str]) -> dict[str, Any]:
    """Prefer explicit upstream bridge API signatures over bare case_meta trigger strings."""
    for cn in canonical_names or []:
        java_sig = cn.replace("#", ".", 1) if "#" in str(cn) else str(cn)
        java_sig = java_sig.strip()
        if java_sig and "(" in java_sig:
            return _api_to_vulnerable_record(java_sig)
    if apis:
        return _api_to_vulnerable_record(apis[0])
    return _api_to_vulnerable_record("")




def _has_file_within(ds_path: Path, names: set[str], max_depth: int = 3) -> bool:
    for p in ds_path.rglob("*"):
        try:
            rel = p.relative_to(ds_path).parts
        except ValueError:
            continue
        if len(rel) > max_depth:
            continue
        if any(part in {".git", ".venv", "venv", "env", "__pycache__", "node_modules"} for part in rel):
            continue
        if p.is_file() and p.name in names:
            return True
    return False


def _has_source_within(ds_path: Path, suffixes: set[str], max_depth: int = 8) -> bool:
    for p in ds_path.rglob("*"):
        if not p.is_file() or p.suffix not in suffixes:
            continue
        try:
            rel = p.relative_to(ds_path).parts
        except ValueError:
            continue
        if len(rel) > max_depth:
            continue
        if any(part in {".git", ".venv", "venv", "env", "__pycache__", "node_modules", "target", "build"} for part in rel):
            continue
        return True
    return False


def _looks_java_project(ds_path: Path) -> bool:
    java_markers = {"pom.xml", "build.gradle", "build.gradle.kts", "gradlew", "mvnw"}
    return _has_file_within(ds_path, java_markers, max_depth=3) or _has_source_within(ds_path, {".java", ".kt", ".scala"})


def _looks_python_project(ds_path: Path) -> bool:
    python_markers = {"pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "tox.ini", "Pipfile"}
    if _has_file_within(ds_path, python_markers, max_depth=3):
        return True
    has_py = _has_source_within(ds_path, {".py"})
    has_java = _has_source_within(ds_path, {".java", ".kt", ".scala"})
    return has_py and not has_java


def _detect_downstream_language(ds_path: Path) -> str:
    if _looks_java_project(ds_path):
        return "java"
    if _looks_python_project(ds_path):
        return "python"
    return ""


def discover_downstream_pairs(dataset_raw: Path) -> list[tuple[str, str, Path, dict[str, Any], str]]:
    """
    Yield (case_id, downstream_name, downstream_path, case_meta_dict, language).
    Java projects keep the existing CodeQL path; Python projects use the AST frontend.
    """
    pairs: list[tuple[str, str, Path, dict[str, Any], str]] = []
    for case_dir in sorted(dataset_raw.iterdir()):
        if not case_dir.is_dir() or not case_dir.name.upper().startswith("CVE-"):
            continue
        meta_path = case_dir / "case_meta.json"
        if not meta_path.is_file():
            continue
        try:
            case_meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        case_id = case_dir.name.strip()
        ds_root = case_dir / "downstream"
        if not ds_root.is_dir():
            continue
        for ds_path in sorted(ds_root.iterdir()):
            if not ds_path.is_dir():
                continue
            language = _detect_downstream_language(ds_path)
            if not language:
                continue
            pairs.append((case_id, ds_path.name, ds_path, case_meta, language))
    return pairs



def _python_package_from_case(case_meta: dict[str, Any]) -> tuple[str, str]:
    for key in ("pypi_package", "python_package", "package_name", "upstream_slug", "upstream_name"):
        val = str(case_meta.get(key) or "").strip()
        if val:
            return val, str(case_meta.get("vulnerable_version") or "")
    coord = str(case_meta.get("maven_coordinate") or "")
    if coord:
        _gid, aid, ver = _parse_maven_coordinate(coord)
        return aid or coord, ver
    return "", str(case_meta.get("vulnerable_version") or "")


def _case_language(languages: list[str]) -> str:
    uniq = sorted(set(x for x in languages if x))
    if len(uniq) == 1:
        return uniq[0]
    return "mixed" if uniq else "unknown"


def build_match_info_for_raw(
    pairs: list[tuple[str, str, Path, dict[str, Any], str]],
    dataset_raw: Path,
    dataset_raw_rel: str,
) -> dict[str, Any]:
    """Build full dataset_match_info.json object keyed by case_id."""
    by_case: dict[str, dict[str, Any]] = {}
    apis_by_case: dict[str, list[str]] = {}
    upstream_bridge_hints_by_case: dict[str, list[str]] = {}
    upstream_bridge_canonical_by_case: dict[str, list[str]] = {}
    languages_by_case: dict[str, list[str]] = {}

    for case_id, ds_name, ds_path, case_meta, language in pairs:
        apis = [str(x) for x in (case_meta.get("candidate_trigger_apis") or []) if str(x).strip()]
        apis_by_case.setdefault(case_id, apis)
        languages_by_case.setdefault(case_id, []).append(language)
        if case_id not in upstream_bridge_hints_by_case:
            u_hints, u_canon = _load_upstream_bridge_apis(dataset_raw / case_id)
            upstream_bridge_hints_by_case[case_id] = u_hints
            upstream_bridge_canonical_by_case[case_id] = u_canon

    for case_id, ds_name, ds_path, case_meta, language in pairs:
        if case_id not in by_case:
            apis = apis_by_case.get(case_id, [])
            u_canon = upstream_bridge_canonical_by_case.get(case_id, [])
            vuln_recs = [_vulnerable_record_for_case(apis, u_canon)]
            case_lang = _case_language(languages_by_case.get(case_id, []))
            coord = str(case_meta.get("maven_coordinate") or "")
            gid, aid, ver = _parse_maven_coordinate(coord)
            py_pkg, py_ver = _python_package_from_case(case_meta)
            poc_rel = f"{dataset_raw_rel}/{case_id}/poc".replace("\\", "/")
            upstream_package = (
                {
                    "name": py_pkg,
                    "affected_version": str(case_meta.get("vulnerable_version") or py_ver),
                    "fixed_version": str(case_meta.get("fixed_version") or ""),
                }
                if case_lang == "python"
                else {
                    "group_id": gid,
                    "artifact_id": aid,
                    "affected_version": str(case_meta.get("vulnerable_version") or ""),
                    "fixed_version": str(case_meta.get("fixed_version") or ""),
                }
            )
            by_case[case_id] = {
                "case_id": case_id,
                "cve_id": case_id,
                "ecosystem": "pypi" if case_lang == "python" else "maven" if case_lang == "java" else "mixed",
                "language": case_lang,
                "dataset_root": f"{dataset_raw_rel}/{case_id}".replace("\\", "/"),
                "upstream": {
                    "name": str(case_meta.get("upstream_slug") or case_meta.get("upstream_name") or "upstream"),
                    "repo": str(case_meta.get("upstream_repo_url") or ""),
                    "checkout": str(case_meta.get("upstream_ref") or ""),
                    "local_path": f"{dataset_raw_rel}/{case_id}/upstream".replace("\\", "/"),
                    "download_status": "existing_valid",
                    "checkout_method": "git",
                    "package": upstream_package,
                },
                "downstreams": [],
                "vulnerable_apis": vuln_recs,
                "poc": {
                    "type": "inline",
                    "local_path": f"{poc_rel}/inline",
                    "payloads": [],
                    "expected_vulnerable_result": "",
                    "expected_patched_behavior": "",
                },
                "notes": ["generated by scripts/run_full_dataset_experiment.py from dataset/raw"],
                "bridge_api_canonical_names": list(upstream_bridge_canonical_by_case.get(case_id, [])),
            }
            (dataset_raw / case_id / "poc" / "inline").mkdir(parents=True, exist_ok=True)

        apis = apis_by_case.get(case_id, [])
        u_hints = upstream_bridge_hints_by_case.get(case_id, [])
        u_canon = upstream_bridge_canonical_by_case.get(case_id, [])
        vuln_recs = [_vulnerable_record_for_case(apis, u_canon)]
        bridge_hints_merged = _merge_bridge_hint_lists(u_hints, _bridge_hints_from_apis(apis))
        local_rel = f"{dataset_raw_rel}/{case_id}/downstream/{ds_name}".replace("\\", "/")
        if language == "python":
            py_pkg, py_ver = _python_package_from_case(case_meta)
            entry = {
                "name": ds_name,
                "repo": "",
                "checkout": "",
                "local_path": local_rel,
                "language": "python",
                "build_system": "python",
                "status": "auto_discovered",
                "download_status": "existing_valid",
                "checkout_method": "git",
                "dependency_hint": {"package": py_pkg, "version": py_ver},
                "build_hint": {"command": "python -m pytest -q"},
                "bridge_hints": bridge_hints_merged,
                "vulnerable_apis": vuln_recs,
                "poc_payload": "",
            }
        else:
            gid, aid, ver = _parse_maven_coordinate(str(case_meta.get("maven_coordinate") or ""))
            entry = {
                "name": ds_name,
                "repo": "",
                "checkout": "",
                "local_path": local_rel,
                "language": "java",
                "build_system": "maven",
                "status": "auto_discovered",
                "download_status": "existing_valid",
                "checkout_method": "git",
                "dependency_hint": {"group_id": gid, "artifact_id": aid, "version": ver},
                "build_hint": {"command": DEFAULT_MAVEN},
                "bridge_hints": bridge_hints_merged,
                "vulnerable_apis": vuln_recs,
                "poc_payload": "",
            }
        by_case[case_id]["downstreams"].append(entry)

    return by_case


def write_pipeline_flowchart(path: Path) -> None:
    """High-level Mermaid flowchart for the three experiment parts."""
    text = """flowchart TB
  subgraph P1["第一部分：静态与调用流"]
    A1[CodeQL database + build] --> A2[Bridge / entry / call-edge queries]
    A2 --> A3[bridge_points.json]
    A2 --> A4[full_callgraph.json + full_callgraph.dot]
    A3 --> A5[method_flow_paths.json + method_flow_graph.dot]
  end
  subgraph P2["第二部分：可达性分析"]
    B1[Parameter CodeQL queries] --> B2[parameter_flow_graph.json]
    B2 --> B3[parameter_reachable_paths.json]
    B3 --> B4[selected_test_paths.json + path_ranking_report.json]
  end
  subgraph P3["第三部分：单元测试生成"]
    C1[load_selected_test_tasks] --> C2[ThirdPhaseOrchestrator]
    C2 --> C3[生成 / 编译 / 运行 / oracle 校验]
  end
  P1 --> P2 --> P3
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _run(cmd: list[str], cwd: Path, log_path: Path | None) -> int:
    if log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)
    if log_path:
        with log_path.open("a", encoding="utf-8") as logf:
            logf.write(f"\n---\n$ {' '.join(cmd)}\n")
            logf.flush()
            p = subprocess.run(cmd, cwd=str(cwd), stdout=logf, stderr=subprocess.STDOUT, text=True)
            return int(p.returncode)
    p = subprocess.run(cmd, cwd=str(cwd))
    return int(p.returncode)



def _load_third_phase_summary(summary_path: Path, rec: dict[str, Any]) -> None:
    rec["third_phase_summary"] = str(summary_path)
    if not summary_path.is_file():
        return
    try:
        third_summary = json.loads(summary_path.read_text(encoding="utf-8"))
        paths = third_summary.get("paths") or []
        rec["third_phase_success"] = bool(third_summary.get("success"))
        rec["third_phase_final_stage"] = third_summary.get("final_stage")
        rec["selected_path_count"] = int(third_summary.get("selected_path_count") or 0)
        rec["attempted_path_count"] = int(third_summary.get("attempted_path_count") or 0)
        rec["generation_rounds"] = sum(int(p.get("rounds") or 0) for p in paths if isinstance(p, dict))
        rec["successful_path_id"] = third_summary.get("successful_path_id")
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        rec["errors"].append(f"third_phase_summary read failed: {exc}")


def run_phases_for_pair(
    *,
    meta_path: Path,
    case_id: str,
    downstream: str,
    language: str,
    codeql_bin: str,
    codeql_force: bool,
    skip_codeql: bool,
    phase1: bool,
    phase2: bool,
    phase3: bool,
    selected_count: int,
    third_max_paths: int,
    third_no_llm: bool,
    third_smoke: bool,
    log_dir: Path,
) -> dict[str, Any]:
    py = sys.executable
    rec: dict[str, Any] = {
        "case_id": case_id,
        "downstream": downstream,
        "language": language,
        "phase1_rc": None,
        "phase2_rc": None,
        "phase3_rc": None,
        "phase3_skipped": False,
        "third_phase_success": None,
        "third_phase_final_stage": None,
        "third_phase_summary": None,
        "selected_path_count": 0,
        "attempted_path_count": 0,
        "generation_rounds": 0,
        "successful_path_id": None,
        "errors": [],
    }
    pair_log = log_dir / case_id / f"{downstream.replace('/', '_')}.log"

    reach_dir = PROJECT_ROOT / "outputs" / "reachability" / case_id / downstream
    pflow = PROJECT_ROOT / "outputs" / "parameter_flows" / case_id / downstream / "parameter_flow_graph.json"
    preach = reach_dir / "parameter_reachable_paths.json"
    sel_out = PROJECT_ROOT / "outputs" / "selected_paths" / case_id / downstream

    if language == "python":
        if phase1 or phase2:
            cmd = [
                py,
                str(PROJECT_ROOT / "scripts" / "run_python_pipeline.py"),
                "--metadata",
                str(meta_path),
                "--case-id",
                case_id,
                "--downstream",
                downstream,
                "--selected-count",
                str(selected_count),
            ]
            rc = _run(cmd, PROJECT_ROOT, pair_log)
            if phase1:
                rec["phase1_rc"] = rc
            if phase2:
                rec["phase2_rc"] = rc
            if rc != 0:
                rec["errors"].append(f"python pipeline exit {rc}")
                return rec
        if phase2 and not (preach.is_file() and pflow.is_file()):
            rec["phase2_rc"] = -2
            rec["errors"].append("python phase2 outputs missing (parameter paths or flow graph)")
            return rec
        if phase3:
            sel_json = sel_out / "selected_test_paths.json"
            if not sel_json.is_file():
                rec["phase3_rc"] = -3
                rec["errors"].append("phase3 missing selected_test_paths.json")
                return rec
            out_root = PROJECT_ROOT / "outputs" / "third_phase" / case_id / downstream
            cmd = [
                py,
                str(PROJECT_ROOT / "scripts" / "run_python_third_phase.py"),
                "--metadata",
                str(meta_path),
                "--case-id",
                case_id,
                "--downstream",
                downstream,
                "--selected-test-paths",
                str(sel_json),
                "--parameter-flow-graph",
                str(pflow),
                "--parameter-reachable-paths",
                str(preach),
                "--output-root",
                str(out_root),
                "--max-paths",
                str(third_max_paths),
            ]
            if third_no_llm:
                cmd.append("--no-llm")
            if third_smoke:
                cmd.append("--deterministic-smoke-only")
            rc = _run(cmd, PROJECT_ROOT, pair_log)
            rec["phase3_rc"] = rc
            if rc != 0:
                rec["errors"].append(f"python phase3 exit {rc}")
            _load_third_phase_summary(out_root / "third_phase_summary.json", rec)
        return rec

    if phase1 and not skip_codeql:
        cmd = [
            py,
            str(PROJECT_ROOT / "scripts" / "run_codeql_pipeline.py"),
            "--metadata",
            str(meta_path),
            "--case-id",
            case_id,
            "--downstream",
            downstream,
            "--codeql-bin",
            codeql_bin,
            "--run-parameter-queries",
            "--build-parameter-flow-graph",
        ]
        if codeql_force:
            cmd.append("--force")
        rc = _run(cmd, PROJECT_ROOT, pair_log)
        rec["phase1_rc"] = rc
        if rc != 0:
            rec["errors"].append(f"phase1 exit {rc}")
            return rec
    elif phase1 and skip_codeql:
        rec["phase1_rc"] = -1
        rec["errors"].append("phase1 skipped (--skip-codeql)")
        return rec

    if phase2:
        if not preach.is_file() or not pflow.is_file():
            rec["phase2_rc"] = -2
            rec["errors"].append("phase2 inputs missing (parameter paths or flow graph)")
        else:
            cmd = [
                py,
                str(PROJECT_ROOT / "scripts" / "select_test_paths.py"),
                "--parameter-reachable-paths",
                str(preach),
                "--parameter-flow-graph",
                str(pflow),
                "--metadata",
                str(meta_path),
                "--case-id",
                case_id,
                "--downstream",
                downstream,
                "--output-dir",
                str(sel_out),
                "--selected-count",
                str(selected_count),
            ]
            rc = _run(cmd, PROJECT_ROOT, pair_log)
            rec["phase2_rc"] = rc
            if rc != 0:
                rec["errors"].append(f"phase2 exit {rc}")
                return rec

            sel_json = sel_out / "selected_test_paths.json"
            if not sel_json.is_file():
                rec["errors"].append("selected_test_paths.json not written")
                return rec
            doc = json.loads(sel_json.read_text(encoding="utf-8"))
            if not (doc.get("selected_paths") or []):
                rec["phase3_skipped"] = True
                rec["errors"].append("no selected_paths; skip phase3")
                return rec

    if phase3:
        sel_json = sel_out / "selected_test_paths.json"
        if rec.get("phase3_skipped"):
            rec["phase3_rc"] = None
            return rec
        if not sel_json.is_file():
            rec["phase3_rc"] = -3
            rec["errors"].append("phase3 missing selected_test_paths.json")
            return rec
        out_root = PROJECT_ROOT / "outputs" / "third_phase" / case_id / downstream
        cmd = [
            py,
            str(PROJECT_ROOT / "scripts" / "run_third_phase.py"),
            "--metadata",
            str(meta_path),
            "--case-id",
            case_id,
            "--downstream",
            downstream,
            "--selected-test-paths",
            str(sel_json),
            "--parameter-flow-graph",
            str(pflow),
            "--parameter-reachable-paths",
            str(preach),
            "--output-root",
            str(out_root),
            "--max-paths",
            str(third_max_paths),
        ]
        if third_no_llm:
            cmd.append("--no-llm")
        if third_smoke:
            cmd.append("--deterministic-smoke-only")
        rc = _run(cmd, PROJECT_ROOT, pair_log)
        rec["phase3_rc"] = rc
        if rc != 0:
            rec["errors"].append(f"phase3 exit {rc}")
        _load_third_phase_summary(out_root / "third_phase_summary.json", rec)
    return rec


def build_formatted_case_results(
    *,
    match_info: dict[str, Any],
    results: list[dict[str, Any]],
    phase3_enabled: bool,
) -> list[dict[str, Any]]:
    """Build a minimal per-pair report."""
    items: list[dict[str, Any]] = []
    for rec in results:
        case_id = str(rec.get("case_id") or "")
        downstream_name = str(rec.get("downstream") or "")
        case_obj = match_info.get(case_id)
        case_doc = case_obj if isinstance(case_obj, dict) else {}
        upstream_obj = case_doc.get("upstream")
        upstream = upstream_obj if isinstance(upstream_obj, dict) else {}
        errors = [str(e) for e in (rec.get("errors") or [])]
        success = bool(rec.get("third_phase_success")) and not errors if phase3_enabled else not errors
        items.append(
            {
                "upstream": upstream.get("name"),
                "downstream": downstream_name,
                "success": success,
                "generation_rounds": int(rec.get("generation_rounds") or 0),
            }
        )
    return items

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="run_full_dataset_experiment",
        description="【主控】对 dataset/raw 下全部 Java 下游串联：①CodeQL/调用与方法流图 ②参数可达与选路 ③单测生成与验证。",
    )
    parser.add_argument(
        "--dataset-raw",
        type=Path,
        default=PROJECT_ROOT / "dataset" / "raw",
        help="Root folder containing CVE-* case directories (default: <project>/dataset/raw)",
    )
    parser.add_argument(
        "--output-metadata",
        type=Path,
        default=PROJECT_ROOT / "outputs" / "full_dataset_run" / "generated_dataset_match_info.json",
        help="Written match_info path (must live under outputs/ so task_adapter resolves project root).",
    )
    parser.add_argument("--flowchart-out", type=Path, default=None, help="Mermaid file (default: next to metadata)")
    parser.add_argument("--codeql-bin", default="codeql")
    parser.add_argument(
        "--no-codeql-force",
        action="store_true",
        help="Do not pass --force to CodeQL pipeline (fail if outputs/codeql_dbs/... already exists).",
    )
    parser.add_argument("--skip-codeql", action="store_true", help="Skip phase 1 (for dry layout only)")
    parser.add_argument("--dry-run", action="store_true", help="Only discover pairs, write metadata + flowchart")
    parser.add_argument("--limit", type=int, default=0, help="Max (case, downstream) pairs to process (0=all)")
    parser.add_argument("--phase", choices=("1", "2", "3", "all"), default="all")
    parser.add_argument("--selected-count", type=int, default=3)
    parser.add_argument("--third-max-paths", type=int, default=3)
    parser.add_argument("--third-no-llm", action="store_true")
    parser.add_argument("--third-smoke-only", action="store_true")
    parser.add_argument("--no-progress", action="store_true", help="禁用 tqdm 进度条（纯文本日志）")
    args = parser.parse_args()

    dataset_raw = args.dataset_raw.resolve()
    if not dataset_raw.is_dir():
        print(f"dataset raw not found: {dataset_raw}", file=sys.stderr)
        return 2

    pairs = discover_downstream_pairs(dataset_raw)
    if args.limit and args.limit > 0:
        pairs = pairs[: args.limit]

    try:
        dataset_raw_rel = dataset_raw.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        print("--dataset-raw must be under project root for relative paths in metadata", file=sys.stderr)
        return 2
    match_info = build_match_info_for_raw(pairs, dataset_raw, dataset_raw_rel)

    out_meta = args.output_metadata.resolve()
    out_meta.parent.mkdir(parents=True, exist_ok=True)
    out_meta.write_text(json.dumps(match_info, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote metadata ({len(match_info)} cases, {len(pairs)} downstream pairs): {out_meta}")

    flow_out = args.flowchart_out or (out_meta.parent / "experiment_pipeline_flowchart.mmd")
    write_pipeline_flowchart(flow_out.resolve())
    print(f"wrote pipeline flowchart: {flow_out.resolve()}")

    if args.dry_run:
        bar = _progress_bar(enumerate(pairs, start=1), total=len(pairs), desc="预览(dry-run)", disable=args.no_progress)
        for i, (cid, ds, path, _meta, lang) in bar:
            msg = f"{cid} / {ds}"
            if tqdm and hasattr(bar, "set_postfix_str"):
                bar.set_postfix_str(msg[:70])  # type: ignore[attr-defined]
            print(f"  [{i}/{len(pairs)}] would run: {cid} / {ds}  [{lang}]  ({path})")
        return 0

    phase1 = args.phase in ("1", "all")
    phase2 = args.phase in ("2", "all")
    phase3 = args.phase in ("3", "all")
    phase_desc = ",".join(lbl for lbl, on in (("1", phase1), ("2", phase2), ("3", phase3)) if on) or "none"
    codeql_force = not args.no_codeql_force

    _print_banner(dataset_raw, len(pairs), phase_desc)

    log_dir = out_meta.parent / "logs"
    results: list[dict[str, Any]] = []
    t0 = time.time()
    bar = _progress_bar(pairs, total=len(pairs), desc="全流程实验", disable=args.no_progress)
    for case_id, ds_name, _path, _meta, lang in bar:
        label = f"{case_id} › {ds_name}"
        if tqdm is not None and not args.no_progress and hasattr(bar, "set_postfix_str"):
            bar.set_postfix_str(label[:65] + ("…" if len(label) > 65 else ""))  # type: ignore[attr-defined]
        rec = run_phases_for_pair(
            meta_path=out_meta,
            case_id=case_id,
            downstream=ds_name,
            language=lang,
            codeql_bin=args.codeql_bin,
            codeql_force=codeql_force,
            skip_codeql=args.skip_codeql,
            phase1=phase1,
            phase2=phase2,
            phase3=phase3,
            selected_count=args.selected_count,
            third_max_paths=args.third_max_paths,
            third_no_llm=args.third_no_llm,
            third_smoke=args.third_smoke_only,
            log_dir=log_dir,
        )
        results.append(rec)
        status = "OK" if not rec.get("errors") else "FAIL"
        if tqdm is not None and not args.no_progress and hasattr(bar, "set_postfix_str"):
            short = (case_id[:14] + "…") if len(case_id) > 15 else case_id
            bar.set_postfix_str(f"{short} | {status}")  # type: ignore[attr-defined]
        if rec.get("errors"):
            err_txt = "; ".join(rec["errors"])
            if tqdm is not None and not args.no_progress:
                tqdm.write(f"[FAIL] {case_id} / {ds_name}: {err_txt}")
            else:
                print(f"[FAIL] {case_id} / {ds_name}: {err_txt}")

    bad = sum(1 for r in results if r.get("errors"))
    formatted_results_path = out_meta.parent / "formatted_case_results.json"
    summary = {
        "dataset_raw": str(dataset_raw),
        "metadata_out": str(out_meta),
        "flowchart": str(flow_out.resolve()),
        "formatted_results_out": str(formatted_results_path),
        "pairs_total": len(pairs),
        "elapsed_sec": round(time.time() - t0, 2),
        "failed_pairs": bad,
        "results": results,
    }
    (out_meta.parent / "experiment_run_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    formatted_report = build_formatted_case_results(
        match_info=match_info,
        results=results,
        phase3_enabled=phase3,
    )
    formatted_results_path.write_text(
        json.dumps(formatted_report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    done_line = (
        f"完成: {out_meta.parent / 'experiment_run_summary.json'} | "
        f"用时 {summary['elapsed_sec']}s | 失败对数 {bad} / {len(pairs)}"
    )
    if tqdm is not None and not args.no_progress:
        tqdm.write(done_line)
    else:
        print(done_line)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
