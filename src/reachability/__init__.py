"""Phase-2 parameter propagation graph (CodeQL-backed, no LLM / no test synthesis)."""

from src.reachability.parameter_graph_builder import build_parameter_flow_outputs
from src.reachability.reachability_analyzer import CallSiteRecord, _read_callsites_and_args

__all__ = ["build_parameter_flow_outputs", "CallSiteRecord", "_read_callsites_and_args"]
