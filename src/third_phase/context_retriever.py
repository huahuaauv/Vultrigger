from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from src.third_phase.models import ContextPack, ContextSnippet, TestTask


def _read_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    raw = path.read_text(encoding="utf-8", errors="replace")
    return raw.splitlines()


def _snippet_window(path: Path, center_line: int, radius: int, kind: str, meta: dict[str, Any]) -> dict[str, Any] | None:
    lines = _read_lines(path)
    if not lines or center_line < 1:
        return None
    start = max(1, center_line - radius)
    end = min(len(lines), center_line + radius)
    text = "\n".join(lines[start - 1 : end])
    return ContextSnippet(
        file=str(path.as_posix()) if path.is_absolute() else str(path),
        start_line=start,
        end_line=end,
        kind=kind,
        text=text,
        meta=meta,
    ).to_dict()


def _find_java_method_line(project_root: Path, signature: str) -> tuple[Path | None, int]:
    if "(" not in signature:
        return None, 0
    head = signature.split("(")[0]
    if "." not in head:
        return None, 0
    qtype, simple = head.rsplit(".", 1)
    rel = "src/main/java/" + qtype.replace(".", "/") + ".java"
    path = project_root / rel
    if not path.is_file():
        return None, 0
    pattern = re.compile(r"\b" + re.escape(simple) + r"\s*\(")
    for i, line in enumerate(_read_lines(path), start=1):
        if pattern.search(line):
            return path, i
    return path, 1


class ContextRetriever:
    def __init__(self, window_radius: int = 30) -> None:
        self.window_radius = window_radius

    def retrieve(self, task: TestTask) -> ContextPack:
        root = Path(task.project_root)
        snippets: list[dict[str, Any]] = []
        files: set[str] = set()
        methods: list[str] = []

        bp = task.bridge_point
        bf = str(bp.get("file") or "")
        bl = int(bp.get("line") or 0)
        if bf and bl > 0:
            bp_path = root / bf.replace("/", os.sep)
            sn = _snippet_window(bp_path, bl, self.window_radius, "bridge_point", {"path_id": task.path_id})
            if sn:
                snippets.append(sn)
                files.add(bf)

        ent = task.entry
        ef = str(ent.get("file") or "")
        el = int(ent.get("line") or 0)
        if ef and el > 0:
            ep = root / ef.replace("/", os.sep)
            sn = _snippet_window(ep, el, self.window_radius, "entry_method", {"signature": ent.get("signature")})
            if sn:
                snippets.append(sn)
                files.add(ef)
        elif str(ent.get("signature") or ""):
            p2, ln2 = _find_java_method_line(root, str(ent.get("signature")))
            if p2 and ln2 > 0:
                rel = str(p2.relative_to(root)).replace("\\", "/")
                sn = _snippet_window(p2, ln2, self.window_radius, "entry_method_resolved", {"signature": ent.get("signature")})
                if sn:
                    snippets.append(sn)
                    files.add(rel)

        pf = task.parameter_flow or {}
        for n in pf.get("nodes") or []:
            if not isinstance(n, dict):
                continue
            fp = str(n.get("file") or "")
            ln = int(n.get("line") or 0)
            if not fp or ln <= 0:
                continue
            pth = root / fp.replace("/", os.sep)
            sn = _snippet_window(
                pth,
                ln,
                min(25, self.window_radius),
                "parameter_flow_node",
                {"expr": n.get("expr"), "kind": n.get("kind")},
            )
            if sn:
                snippets.append(sn)
                files.add(fp)

        for node in (task.method_path or [])[:5]:
            if not isinstance(node, dict):
                continue
            sig = str(node.get("signature") or "")
            if sig:
                methods.append(sig)
            p2, ln2 = _find_java_method_line(root, sig)
            if p2 and ln2 > 0:
                rel = str(p2.relative_to(root)).replace("\\", "/")
                sn = _snippet_window(p2, ln2, self.window_radius, "method_path", {"signature": sig})
                if sn:
                    snippets.append(sn)
                    files.add(rel)

        test_dir = root / "src" / "test" / "java"
        search_terms = [
            str(bp.get("enclosing_type") or "").split(".")[-1],
            str(ent.get("declaring_type") or "").split(".")[-1],
            "RestRequest",
            "SFTrustManager",
            "HttpGet",
            "HttpPost",
            "URIBuilder",
        ]
        hits = 0
        if test_dir.is_dir():
            for java in sorted(test_dir.rglob("*.java")):
                if hits >= 12:
                    break
                try:
                    text = java.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                for term in search_terms:
                    if not term or len(term) < 3:
                        continue
                    if term in text:
                        lines = text.splitlines()
                        for i, line in enumerate(lines, start=1):
                            if term in line and any(k in line for k in ("new ", ".", "(", "Http")):
                                sn = _snippet_window(java, i, 12, "existing_test_usage", {"term": term})
                                if sn:
                                    snippets.append(sn)
                                    files.add(str(java.relative_to(root)).replace("\\", "/"))
                                    hits += 1
                                break
                        if hits >= 12:
                            break

        for pom_name in ("pom.xml", "public_pom.xml"):
            pom = root / pom_name
            if pom.is_file():
                lines = _read_lines(pom)
                head = "\n".join(lines[:80])
                snippets.append(
                    ContextSnippet(
                        file=str(pom.relative_to(root)).replace("\\", "/"),
                        start_line=1,
                        end_line=min(80, len(lines)),
                        kind="pom_header",
                        text=head,
                        meta={"artifact": pom_name},
                    ).to_dict()
                )
                files.add(pom_name)

        notes = [
            f"reachability_status={task.reachability_status} (parameter_candidate vs confirmed affects evidence strength, not path selection).",
            f"carrier_status={task.carrier.get('status')} name={task.carrier.get('name')} type_hint={task.carrier.get('type_hint')}",
            f"bridge_argument/carrier evidence: {task.carrier.get('evidence')}",
            "Do not access real network; keep tests local/offline.",
            f"oracle_type={task.oracle.get('type')} expected_vulnerable_host={task.oracle.get('expected_vulnerable_host')}",
        ]

        return ContextPack(
            files=sorted(files),
            methods=methods,
            snippets=snippets,
            notes=notes,
            metadata={"path_id": task.path_id, "case_id": task.case_id},
        )
