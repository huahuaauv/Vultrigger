from __future__ import annotations

import csv
import json
import shlex
import shutil
from pathlib import Path
from typing import Any

from .cmd import CmdResult, run_cmd


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def run_codeql_version_check(codeql_bin: str) -> CmdResult:
    return run_cmd([codeql_bin, "--version"], timeout_sec=30)


def create_database(
    codeql_bin: str,
    db_path: Path,
    source_root: Path,
    build_command: str,
    log_path: Path,
    force: bool,
) -> CmdResult:
    if force and db_path.exists():
        shutil.rmtree(db_path)
    ensure_dir(db_path.parent)
    cmd = [
        codeql_bin,
        "database",
        "create",
        str(db_path),
        "--language=java-kotlin",
        "--source-root",
        str(source_root),
        "--command",
        build_command,
    ]
    return run_cmd(cmd, cwd=source_root, timeout_sec=7200, log_path=log_path)


def run_query(codeql_bin: str, query_file: Path, db_path: Path, bqrs_path: Path, log_path: Path) -> CmdResult:
    ensure_dir(bqrs_path.parent)
    cmd = [
        codeql_bin,
        "query",
        "run",
        str(query_file),
        "--database",
        str(db_path),
        "--output",
        str(bqrs_path),
    ]
    return run_cmd(cmd, timeout_sec=1800, log_path=log_path)


def decode_bqrs(codeql_bin: str, bqrs_path: Path, csv_path: Path, log_path: Path) -> CmdResult:
    ensure_dir(csv_path.parent)
    cmd = [
        codeql_bin,
        "bqrs",
        "decode",
        str(bqrs_path),
        "--format=csv",
        "--output",
        str(csv_path),
    ]
    return run_cmd(cmd, timeout_sec=600, log_path=log_path)


def csv_to_json(csv_path: Path, json_path: Path, headers: list[str]) -> int:
    ensure_dir(json_path.parent)
    rows: list[dict[str, Any]] = []
    if csv_path.exists():
        with csv_path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.reader(f)
            for raw in reader:
                if not raw:
                    continue
                if raw[0] in {"col0", headers[0]}:
                    continue
                if len(raw) < len(headers):
                    raw += [""] * (len(headers) - len(raw))
                rows.append({headers[idx]: raw[idx] for idx in range(len(headers))})
    json_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    return len(rows)


def parse_build_command(build_command: str) -> list[str]:
    return shlex.split(build_command, posix=False)
