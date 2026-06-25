from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


def default_oracle() -> dict[str, Any]:
    return {
        "type": "host_mismatch_assertion",
        "payload": "http://user@apache.org:80@google.com/",
        "expected_vulnerable_host": "apache.org",
        "safe_host": "google.com",
        "must_avoid_real_network": True,
    }


@dataclass
class TestTask:
    case_id: str
    cve_id: str
    downstream: str
    project_root: str
    path_id: str
    rank: int
    score: float
    reachability_status: str
    entry: dict[str, Any]
    bridge_point: dict[str, Any]
    carrier: dict[str, Any]
    method_path: list[dict[str, Any]]
    parameter_flow: dict[str, Any]
    payload: str
    oracle: dict[str, Any]
    test_generation_hints: dict[str, Any]
    selected_path_raw: dict[str, Any]
    selection_reason: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ContextSnippet:
    file: str
    start_line: int
    end_line: int
    kind: str
    text: str
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ContextPack:
    files: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)
    snippets: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PromptPackage:
    system_prompt: str
    user_prompt: str
    entry_method: str
    selected_path: dict[str, Any]
    coding_contract: str
    oracle_spec: dict[str, Any]
    verifier_package: dict[str, Any]
    test_plan: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GenerationResult:
    success: bool
    test_file_relpath: str
    test_class_name: str
    test_method_name: str
    method_body: str
    method_body_b64: str
    validated_ok: bool
    validation_errors: list[str]
    raw_model_output: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RunSummary:
    compile_success: bool
    run_success: bool
    bridge_hit: bool
    payload_observed_at_bridge: bool
    vulnerability_behavior_observed: bool
    vuln_api_invoked: bool
    runtime_logs: str
    compile_excerpt: str
    run_excerpt: str
    markers: dict[str, Any]
    generated_test_path: str
    failure_stage: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Verdict:
    judgement: str
    confidence: str
    reason: str
    key_matched_evidence: list[str]
    key_differences: list[str]
    next_action: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DebugBoard:
    status: str
    root_cause_top3: list[str]
    action_items: list[str]
    evidence: list[str]
    do_not_repeat: list[str]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
