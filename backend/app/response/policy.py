"""Deterministic response policy for canonical security events."""

from __future__ import annotations

from typing import Any, Dict

from .models import ResponseDecision


POLICY_ID = "response.default.v1"


def evaluate_event(event: Dict[str, Any]) -> ResponseDecision:
    """
    Evaluate a canonical security event without executing any action.

    Response authority is deliberately separated from detection:
    this function only decides what should happen.
    """

    severity = str(event.get("severity", "medium")).lower()
    confidence = float(event.get("confidence", 0.0))
    occurrences = int(event.get("occurrence_count", 1))
    status = str(event.get("status", "open")).lower()

    if status == "resolved":
        return ResponseDecision(
            action="observe",
            policy_id=POLICY_ID,
            reason="resolved events require no further response",
        )

    if severity == "critical" and confidence >= 0.90 and occurrences >= 3:
        return ResponseDecision(
            action="contain",
            policy_id=POLICY_ID,
            reason=(
                "critical event has high confidence and repeated occurrences"
            ),
            requires_approval=True,
        )

    if (
        severity in {"high", "critical"}
        and confidence >= 0.75
        and occurrences >= 2
    ):
        return ResponseDecision(
            action="notify",
            policy_id=POLICY_ID,
            reason=(
                "high-confidence high-severity event has repeated occurrences"
            ),
        )

    return ResponseDecision(
        action="observe",
        policy_id=POLICY_ID,
        reason="event does not meet response threshold",
    )
