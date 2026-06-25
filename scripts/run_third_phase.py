from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from src.pipeline.run_third_phase import main as m

    return m()


if __name__ == "__main__":
    raise SystemExit(main())
