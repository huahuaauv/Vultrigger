from __future__ import annotations

from dataclasses import dataclass

CarrierStatus = str  # confirmed | strong_candidate | candidate | unknown


@dataclass
class CallSiteRecord:
    """Legacy record for third_phase context_retriever (optional CSV index)."""

    file: str
    start_line: int
    caller: str = ""
    callee: str = ""
