"""
第三阶段 v2：消费 selected_test_paths + 参数流图产物，多智能体生成 JUnit 方法体，
由 Executor 插桩 / Maven 与 Verifier 确定性门禁判定成功（非 LLM 自判）。
"""

__all__ = ["ThirdPhaseOrchestrator", "load_selected_test_tasks"]


def __getattr__(name: str):
    if name == "ThirdPhaseOrchestrator":
        from src.third_phase.orchestrator import ThirdPhaseOrchestrator

        return ThirdPhaseOrchestrator
    if name == "load_selected_test_tasks":
        from src.third_phase.task_adapter import load_selected_test_tasks

        return load_selected_test_tasks
    raise AttributeError(name)
