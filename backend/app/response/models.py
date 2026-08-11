"""Response-engine data contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


ResponseAction = Literal[
    "observe",
    "notify",
    "contain",
]


@dataclass(frozen=True)
class ResponseDecision:
    """Deterministic response decision for a security event."""

    action: ResponseAction
    policy_id: str
    reason: str
    requires_approval: bool = False
