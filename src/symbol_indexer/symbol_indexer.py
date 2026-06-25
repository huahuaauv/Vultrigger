from __future__ import annotations

from pathlib import Path


def index_symbols(project_root: Path) -> dict:
    return {"project_root": str(project_root), "symbols": []}
