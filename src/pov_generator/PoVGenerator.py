import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class PoVPrompt:
    """
    面向 LLM 的 PoV 生成提示。
    你可以把它序列化为 JSON，或拼成纯文本。
    """

    title: str
    context: Dict[str, Any]
    instructions: List[str]


class PoVGenerator:
    """
    作用：
    - 读取：
      - vulbridge.json
      - parameter_bridge_graph.json
      -（可选）poc_index.json / manifest.json
    - 生成一个可直接给 LLM 使用的 PoV prompt 文件（默认：pov_prompt.json）
    """

    def __init__(
        self,
        vulbridge_json: Path,
        parameter_bridge_graph_json: Path,
        output_dir: Path,
        poc_index_json: Optional[Path] = None,
        manifest_json: Optional[Path] = None,
    ) -> None:
        self.vulbridge_json = vulbridge_json
        self.parameter_bridge_graph_json = parameter_bridge_graph_json
        self.poc_index_json = poc_index_json
        self.manifest_json = manifest_json
        self.output_dir = output_dir

    @staticmethod
    def _read_json(path: Optional[Path]) -> Optional[Dict[str, Any]]:
        if not path or not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def _build_prompt(self) -> PoVPrompt:
        vulbridge = self._read_json(self.vulbridge_json) or {}
        param_graph = self._read_json(self.parameter_bridge_graph_json) or {}
        poc_index = self._read_json(self.poc_index_json) if self.poc_index_json else None
        manifest = self._read_json(self.manifest_json) if self.manifest_json else None

        bridge_points = (vulbridge.get("bridge_points") or []) if isinstance(vulbridge.get("bridge_points"), list) else []
        user_controlled = [b for b in bridge_points if isinstance(b, dict) and b.get("is_user_controlled") is True]

        oracle_hint = None
        if manifest and isinstance(manifest.get("poc"), dict):
            oracle_hint = manifest["poc"].get("oracle_hint")

        # 从 poc_index 中挑一个最“可信”的 PoC
        poc_best = None
        if poc_index and isinstance(poc_index.get("pocs"), list):
            for rec in poc_index["pocs"]:
                if isinstance(rec, dict) and rec.get("valid") is True:
                    poc_best = rec
                    break

        ctx: Dict[str, Any] = {
            "bridge_points_total": len(bridge_points),
            "bridge_points_user_controlled": user_controlled,
            "parameter_bridge_graph_edges": (param_graph.get("edges") if isinstance(param_graph.get("edges"), list) else []),
            "poc": poc_best,
            "oracle_hint": oracle_hint,
            "limitations": [
                "桥接点/参数流基于调用图近似分析；若需要精确 callsite 与参数表达式，需要补充 AST/IR 分析。",
            ],
        }

        instructions = [
            "根据 bridge_points_user_controlled 中的桥接点，设计一个能把用户可控数据传递到上游漏洞 API 的 PoV。",
            "如果 poc 提供了输入文件，优先围绕该 PoC 变种/拼接生成新的 PoV（例如修改关键字段、长度、嵌套层级）。",
            "给出清晰的 oracle：如何判定触发成功（例如 crash/timeout/异常日志/返回码）。",
            "输出需要包含：触发路径说明（下游函数 -> 上游漏洞 API）、关键参数位置、以及执行步骤。",
        ]
        if oracle_hint and isinstance(oracle_hint, str) and oracle_hint.strip():
            instructions.append(f"实验 oracle_hint（来自数据集）：{oracle_hint.strip()}")

        return PoVPrompt(
            title="PoV generation prompt (bridge points + parameter flow + PoC context)",
            context=ctx,
            instructions=instructions,
        )

    def run(self, output_basename: str = "pov_prompt.json") -> Path:
        if not self.output_dir.exists():
            self.output_dir.mkdir(parents=True, exist_ok=True)

        prompt = self._build_prompt()
        out = self.output_dir / output_basename
        with out.open("w", encoding="utf-8") as f:
            json.dump(
                {
                    "title": prompt.title,
                    "context": prompt.context,
                    "instructions": prompt.instructions,
                },
                f,
                ensure_ascii=False,
                indent=2,
            )
        return out


def main() -> None:
    parser = argparse.ArgumentParser(description="根据 vulbridge/参数流/PoC 信息生成 LLM 用 PoV prompt 文件")
    parser.add_argument("vulbridge_json", help="vulbridge.json 路径")
    parser.add_argument("parameter_bridge_graph_json", help="parameter_bridge_graph.json 路径")
    parser.add_argument("output_dir", help="输出目录")
    parser.add_argument("--poc-index", default=None, help="可选：poc_index.json 路径")
    parser.add_argument("--manifest", default=None, help="可选：样本 manifest.json 路径（用于 oracle_hint）")
    parser.add_argument("--out", default="pov_prompt.json", help="输出文件名（默认 pov_prompt.json）")
    args = parser.parse_args()

    gen = PoVGenerator(
        vulbridge_json=Path(args.vulbridge_json),
        parameter_bridge_graph_json=Path(args.parameter_bridge_graph_json),
        output_dir=Path(args.output_dir),
        poc_index_json=Path(args.poc_index) if args.poc_index else None,
        manifest_json=Path(args.manifest) if args.manifest else None,
    )
    out = gen.run(output_basename=args.out)
    print(f"已生成: {out.resolve()}")


if __name__ == "__main__":
    main()

