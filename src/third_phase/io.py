from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: Any, *, indent: int = 2) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=indent), encoding="utf-8")


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def safe_relpath(path: Path, base: Path) -> str:
    try:
        return str(path.resolve().relative_to(base.resolve()))
    except ValueError:
        return str(path)


def write_text(path: Path, text: str) -> None:
    ensure_dir(path.parent)
    path.write_text(text, encoding="utf-8")


def timestamp_run_id() -> str:
    return f"{int(time.time())}-{uuid.uuid4().hex[:8]}"
