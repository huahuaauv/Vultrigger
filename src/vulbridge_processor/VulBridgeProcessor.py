from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class VulBridgeProcessor:
    def __init__(self, metadata_path: Path) -> None:
        self.metadata_path = metadata_path

    def _load_json(self, path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []

    def _to_int(self, value: Any) -> int:
        try:
            return int(value)
        except Exception:  # noqa: BLE001
            return 0

    def generate_bridge_points(
        self,
        case_id: str,
        downstream_name: str,
        direct_json_path: Path,
        indirect_json_path: Path,
        codeql_db_path: Path,
        output_path: Path,
    ) -> dict[str, Any]:
        metadata = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        case = metadata[case_id]
        downstream = next(d for d in case.get("downstreams", []) if d.get("name") == downstream_name)
        vulnerable_api = (case.get("vulnerable_apis") or [{}])[0]

        direct_rows = self._load_json(direct_json_path)
        indirect_rows = self._load_json(indirect_json_path)

        bridges: list[dict[str, Any]] = []
        for row in direct_rows:
            bridges.append(
                {
                    "kind": "direct",
                    "confidence": row.get("confidence", "direct"),
                    "file": row.get("file", ""),
                    "line": self._to_int(row.get("line", 0)),
                    "enclosing_type": row.get("enclosing_type", ""),
                    "enclosing_method": row.get("enclosing_method", ""),
                    "callee_signature": row.get("callee_signature", ""),
                    "argument": row.get("argument", ""),
                    "source_query": "DirectBridgePoints.ql",
                }
            )
        for row in indirect_rows:
            bridges.append(
                {
                    "kind": "indirect",
                    "confidence": row.get("confidence", "indirect"),
                    "file": row.get("file", ""),
                    "line": self._to_int(row.get("line", 0)),
                    "enclosing_type": row.get("enclosing_type", ""),
                    "enclosing_method": row.get("enclosing_method", ""),
                    "sink_signature": row.get("sink_signature", ""),
                    "argument": row.get("argument", ""),
                    "source_query": "HttpClientIndirectSinks.ql",
                }
            )

        result = {
            "case_id": case_id,
            "cve_id": case.get("cve_id", case_id),
            "analysis_engine": "codeql",
            "downstream": {
                "name": downstream_name,
                "local_path": downstream.get("local_path", ""),
                "codeql_database": str(codeql_db_path),
            },
            "vulnerable_api": {
                "class_name": vulnerable_api.get("class_name", ""),
                "method_name": vulnerable_api.get("method_name", ""),
                "signature": vulnerable_api.get("signature", ""),
            },
            "bridge_points": bridges,
            "summary": {
                "direct_bridge_points": len(direct_rows),
                "indirect_bridge_points": len(indirect_rows),
                "total_bridge_points": len(bridges),
            },
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        return result
