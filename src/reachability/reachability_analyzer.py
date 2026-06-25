from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from src.reachability.models import CallSiteRecord
from src.reachability.parameter_graph_builder import build_parameter_flow_outputs

__all__ = ["CallSiteRecord", "_read_callsites_and_args", "build_parameter_flow_outputs"]


def _read_callsites_and_args(
    callsites_csv: Path,
    callargs_csv: Path,
) -> dict[tuple[str, str], list[CallSiteRecord]]:
    """Best-effort index for third_phase; returns empty if files are missing."""
    if not callsites_csv.is_file() or not callargs_csv.is_file():
        return {}
    out: dict[tuple[str, str], list[CallSiteRecord]] = {}
    try:
        with callsites_csv.open(encoding="utf-8", newline="") as f:
            rdr = csv.DictReader(f)
            for row in rdr:
                caller = str(row.get("caller", "") or row.get("caller_signature", ""))
                callee = str(row.get("callee", "") or row.get("callee_signature", ""))
                fp = str(row.get("file", "") or row.get("path", ""))
                ln = int(row.get("line", 0) or row.get("start_line", 0) or 0)
                key = (caller, callee)
                out.setdefault(key, []).append(CallSiteRecord(file=fp, start_line=ln, caller=caller, callee=callee))
    except (OSError, ValueError, csv.Error):
        return {}
    return out
