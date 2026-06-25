from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass


@dataclass
class CheckResult:
    name: str
    ok: bool
    output: str


def run_check(cmd: list[str], name: str) -> CheckResult:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    except FileNotFoundError:
        return CheckResult(name=name, ok=False, output=f"{cmd[0]} not found in PATH")
    except Exception as exc:  # noqa: BLE001
        return CheckResult(name=name, ok=False, output=str(exc))
    output = (proc.stdout or "") + (proc.stderr or "")
    return CheckResult(name=name, ok=(proc.returncode == 0), output=output.strip())


def main() -> int:
    checks = [
        run_check(["codeql", "--version"], "codeql"),
        run_check(["java", "-version"], "java"),
        run_check(["mvn", "-version"], "mvn"),
    ]

    for item in checks:
        state = "OK" if item.ok else "FAIL"
        print(f"[{state}] {item.name}")
        if item.output:
            print(item.output)
            print("")

    codeql_item = next(c for c in checks if c.name == "codeql")
    if not codeql_item.ok:
        print("CodeQL environment check failed: codeql is required.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
