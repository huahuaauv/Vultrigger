from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from src.third_phase.models import ContextPack, TestTask


def _read_text(p: Path) -> str:
    if not p.is_file():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def _package_from_java(src: str) -> str:
    m = re.search(r"^\s*package\s+([\w.]+)\s*;", src, re.MULTILINE)
    return m.group(1).strip() if m else ""


def _class_name_from_path(path: Path) -> str:
    return path.stem


def _parse_public_methods(src: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in re.finditer(
        r"(public|protected|private)\s+(?:static\s+)?(?:final\s+)?(?:<[^>]+>\s+)?([\w.<>,\[\]\s]+?)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[\w.,\s]+)?\s*\{",
        src,
        re.MULTILINE,
    ):
        vis, ret, name, params = m.groups()
        out.append(
            {
                "visibility": vis.strip(),
                "return_type": ret.strip(),
                "name": name.strip(),
                "parameters_raw": params.strip(),
                "is_static": "static" in m.group(0),
            }
        )
    return out


def _parse_constructors(src: str) -> list[str]:
    names: list[str] = []
    for m in re.finditer(r"^\s*(public|protected|private)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[\w.,\s]+)?\s*\{", src, re.MULTILINE):
        names.append(m.group(2))
    return names


def _entry_method_facts(src: str, method_simple: str) -> dict[str, Any]:
    pat = re.compile(
        rf"(public|protected|private)\s+(?:static\s+)?(?:final\s+)?(?:<[^>]+>\s+)?([\w.<>,\[\]\s]+?)\s+{re.escape(method_simple)}\s*\(([^)]*)\)",
        re.MULTILINE,
    )
    m = pat.search(src)
    if not m:
        return {"found": False}
    vis, ret, params = m.groups()
    return {
        "found": True,
        "visibility": vis,
        "return_type": ret.strip(),
        "is_static": "static" in m.group(0),
        "parameters_raw": params.strip(),
    }


def _junit_version_from_pom(pom_text: str) -> str:
    if "junit-jupiter" in pom_text or "jupiter" in pom_text:
        return "junit5"
    if "junit" in pom_text.lower():
        return "junit4"
    return "unknown"


def _mockito_from_pom(pom_text: str) -> bool:
    return "mockito" in pom_text.lower()


def _httpclient_from_pom(pom_text: str) -> list[str]:
    out: list[str] = []
    for m in re.finditer(
        r"<artifactId>httpclient</artifactId>\s*<version>([^<]+)</version>",
        pom_text,
        re.IGNORECASE | re.DOTALL,
    ):
        out.append(m.group(1).strip())
    return out


def _surefire_from_pom(pom_text: str) -> str:
    m = re.search(r"<artifactId>maven-surefire-plugin</artifactId>[\s\S]*?</plugin>", pom_text, re.IGNORECASE)
    return (m.group(0)[:2000] + "…") if m else ""


def _third_phase_template_imports() -> list[str]:
    tplp = Path(__file__).resolve().parent / "templates" / "test_class_template.java"
    if not tplp.is_file():
        return []
    src = _read_text(tplp)
    return [m.group(0).strip() for m in re.finditer(r"^\s*import\s+[^;]+;", src, re.MULTILINE)]


def _assembly_templates(project_root: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    test_dir = project_root / "src" / "test" / "java"
    if not test_dir.is_dir():
        return out
    keys = ("RestRequest", "SFTrustManager", "HttpGet", "HttpPost", "URIBuilder", "CloseableHttpClient", "URIUtils")
    for java in list(test_dir.rglob("*.java"))[:400]:
        try:
            t = java.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not any(k in t for k in keys):
            continue
        for line in t.splitlines():
            if any(k in line for k in keys) and ("new " in line or "execute" in line or "setURI" in line):
                out.append(
                    {
                        "file": str(java.relative_to(project_root)).replace("\\", "/"),
                        "line_sample": line.strip()[:240],
                    }
                )
                break
        if len(out) >= 20:
            break
    return out


def build_api_facts(project_root: Path, task: TestTask, context_pack: ContextPack) -> dict[str, Any]:
    root = project_root.resolve()
    entry_sig = str(task.entry.get("signature") or "")
    entry_simple = str(task.entry.get("method") or "")
    if "(" in entry_sig:
        entry_simple = entry_sig.split("(")[0].split(".")[-1]

    ent_rel = str(task.entry.get("file") or "")
    ent_path = root / ent_rel.replace("/", os.sep) if ent_rel else Path()
    entry_src = _read_text(ent_path) if ent_rel else ""
    if not entry_src and entry_sig:
        qtype = str(task.entry.get("declaring_type") or "")
        if qtype:
            cand = root / "src/main/java" / (qtype.replace(".", "/") + ".java")
            entry_src = _read_text(cand)
            ent_path = cand

    entry_pkg = _package_from_java(entry_src)
    entry_class = _class_name_from_path(ent_path) if ent_path.name else ""

    bp = task.bridge_point
    bridge_rel = str(bp.get("file") or "")
    bridge_path = root / bridge_rel.replace("/", os.sep) if bridge_rel else Path()
    bridge_src = _read_text(bridge_path)
    bridge_pkg = _package_from_java(bridge_src)
    bridge_class = _class_name_from_path(bridge_path) if bridge_path.name else ""
    bridge_method = str(bp.get("enclosing_method") or "")
    bridge_method_facts = _entry_method_facts(bridge_src, bridge_method) if bridge_method else {"found": False}

    pom = _read_text(root / "pom.xml")
    pub = _read_text(root / "public_pom.xml")

    carrier_ev = task.carrier.get("evidence") or []
    chain_summary = " ".join(str(x) for x in carrier_ev)

    return {
        "entry_class": {
            "class_name": entry_class,
            "package": entry_pkg,
            "constructors": _parse_constructors(entry_src),
            "public_methods": _parse_public_methods(entry_src)[:80],
            "entry_method_signature": entry_sig,
            "entry_method_facts": _entry_method_facts(entry_src, entry_simple) if entry_simple else {},
            "source_file": ent_rel,
        },
        "bridge_enclosing_class": {
            "class_name": bridge_class,
            "package": bridge_pkg,
            "constructors": _parse_constructors(bridge_src),
            "bridge_method": bridge_method,
            "bridge_method_facts": bridge_method_facts,
            "source_file": bridge_rel,
        },
        "carrier": {
            "name": task.carrier.get("name"),
            "type_hint": task.carrier.get("type_hint"),
            "status": task.carrier.get("status"),
            "bridge_argument_text": task.carrier.get("name"),
            "bridge_argument_type": task.carrier.get("type_hint"),
            "local_carrier_chain_summary": chain_summary,
        },
        "test_framework": {
            "junit": _junit_version_from_pom(pom + pub),
            "mockito_available": _mockito_from_pom(pom + pub),
            "httpclient_version_hints": _httpclient_from_pom(pom + pub),
            "surefire_snippet": _surefire_from_pom(pom),
        },
        "template_imports": _third_phase_template_imports(),
        "existing_test_usage": {
            "assembly_templates": _assembly_templates(root),
        },
        "context_digest": {
            "snippet_count": len(context_pack.snippets),
            "files_in_context": len(context_pack.files),
        },
    }
