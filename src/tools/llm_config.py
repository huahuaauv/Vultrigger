from __future__ import annotations

from dataclasses import dataclass


@dataclass
class LLMConfig:
    provider: str = "unset"
    model: str = "unset"
    temperature: float = 0.0
