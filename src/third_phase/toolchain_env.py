"""Prefer project-local JDK 8 + Maven under tools/ when present (Windows-friendly)."""

from __future__ import annotations

import os
from pathlib import Path


def prepend_project_toolchain(project_root: Path) -> None:
    tools = project_root / "tools"
    jdk = tools / "jdk8"
    java_exe = jdk / "bin" / ("java.exe" if os.name == "nt" else "java")
    if java_exe.is_file():
        os.environ["JAVA_HOME"] = str(jdk.resolve())
        jb = str((jdk / "bin").resolve())
        os.environ["PATH"] = jb + os.pathsep + os.environ.get("PATH", "")

    candidates = sorted(tools.glob("apache-maven-*"), key=lambda p: p.name, reverse=True)
    for d in candidates:
        mvn_bin = d / "bin"
        mvn = mvn_bin / ("mvn.cmd" if os.name == "nt" else "mvn")
        if mvn.is_file():
            os.environ["MAVEN_HOME"] = str(d.resolve())
            os.environ["PATH"] = str(mvn_bin.resolve()) + os.pathsep + os.environ.get("PATH", "")
            break
