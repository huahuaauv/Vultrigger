"""
Legacy symbol-JSON call graph export; primary CodeQL path is
``src.cal_graph_builder.from_codeql_csv.build_call_graph_from_codeql_edges``.
"""
import argparse
import csv
import json
from collections import deque, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set


@dataclass
class Node:
    name: str
    file: str
    line: int


class CallGraph:
    def __init__(self) -> None:
        self.nodes: Dict[str, Node] = {}
        self.edges: Dict[str, List[str]] = defaultdict(list)

    def ensure_node(self, name: str, file: str, line: int) -> None:
        if name not in self.nodes:
            self.nodes[name] = Node(name=name, file=file, line=line)

    def add_edge(self, caller: str, callee: str) -> None:
        self.edges[caller].append(callee)


def build_graph_from_symbols(json_path: Path) -> CallGraph:
    content = json_path.read_text(encoding="utf-8")
    root = json.loads(content)
    symbols = root.get("symbols") or []

    graph = CallGraph()

    # 注册节点
    for s in symbols:
        if not isinstance(s, dict):
            continue
        name = s.get("name")
        if not name:
            continue
        file = s.get("file", "")
        line = int(s.get("line", -1))
        graph.ensure_node(name, file, line)

    # 添加边
    for s in symbols:
        if not isinstance(s, dict):
            continue
        caller = s.get("name")
        if not caller:
            continue
        calls = s.get("calls")
        if not isinstance(calls, list):
            continue
        for callee in calls:
            if not isinstance(callee, str) or not callee:
                continue
            graph.add_edge(caller, callee)

    return graph


def filter_potential_vuln_paths(graph: CallGraph) -> CallGraph:
    """
    非常简单的过滤示例：
    - 名称中包含 user/input/request 的函数视为入口；
    - 从这些入口做 BFS，仅保留可达子图。
    """
    entry_points: Set[str] = set()
    for name in graph.nodes:
        lower = name.lower()
        if "user" in lower or "input" in lower or "request" in lower:
            entry_points.add(name)

    if not entry_points:
        return graph

    filtered = CallGraph()
    visited: Set[str] = set(entry_points)
    queue: deque[str] = deque(entry_points)

    while queue:
        cur = queue.popleft()
        node = graph.nodes.get(cur)
        if not node:
            continue
        filtered.ensure_node(node.name, node.file, node.line)

        for callee in graph.edges.get(cur, []):
            callee_node = graph.nodes.get(callee)
            if not callee_node:
                continue
            filtered.ensure_node(callee_node.name, callee_node.file, callee_node.line)
            filtered.add_edge(node.name, callee_node.name)
            if callee not in visited:
                visited.add(callee)
                queue.append(callee)

    return filtered


def write_csv(csv_path: Path, graph: CallGraph) -> None:
    if not csv_path.parent.exists():
        csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["caller", "callee"])
        for caller, callees in graph.edges.items():
            for callee in callees:
                writer.writerow([caller, callee])


def write_dot(dot_path: Path, graph: CallGraph, graph_name: str) -> None:
    if not dot_path.parent.exists():
        dot_path.parent.mkdir(parents=True, exist_ok=True)
    with dot_path.open("w", encoding="utf-8") as f:
        f.write(f"digraph {graph_name} {{\n")
        for node in graph.nodes.values():
            label = f"{node.name}\\n{node.file}:{node.line}"
            f.write(f'  "{node.name}" [label="{label}"];\n')
        for caller, callees in graph.edges.items():
            for callee in callees:
                f.write(f'  "{caller}" -> "{callee}";\n')
        f.write("}\n")


def export_graph(prefix: str, graph: CallGraph, output_dir: Path) -> None:
    filtered = filter_potential_vuln_paths(graph)
    csv_path = output_dir / f"{prefix}_callgraph.csv"
    dot_path = output_dir / f"{prefix}_callgraph.dot"
    write_csv(csv_path, filtered)
    write_dot(dot_path, filtered, prefix)
    print(f"已导出调用图 CSV: {csv_path.resolve()}")
    print(f"已导出调用图 DOT: {dot_path.resolve()}")


def build_call_graphs(upstream_symbols: Path | None, downstream_symbols: Path | None, output_dir: Path) -> None:
    if not output_dir.exists():
        output_dir.mkdir(parents=True, exist_ok=True)

    if upstream_symbols and upstream_symbols.is_file():
        up_graph = build_graph_from_symbols(upstream_symbols)
        export_graph("upstream", up_graph, output_dir)
    else:
        print(f"未找到上游符号文件: {upstream_symbols}")

    if downstream_symbols and downstream_symbols.is_file():
        down_graph = build_graph_from_symbols(downstream_symbols)
        export_graph("downstream", down_graph, output_dir)
    else:
        print(f"未找到下游符号文件: {downstream_symbols}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="根据符号 JSON 构建调用图，并导出 CSV 与 DOT 文件",
    )
    parser.add_argument("upstream_symbols", help="upstream_symbols.json 路径")
    parser.add_argument("downstream_symbols", help="downstream_symbols.json 路径")
    parser.add_argument("output_dir", help="调用图输出目录")
    args = parser.parse_args()

    build_call_graphs(
        Path(args.upstream_symbols),
        Path(args.downstream_symbols),
        Path(args.output_dir),
    )


if __name__ == "__main__":
    main()

