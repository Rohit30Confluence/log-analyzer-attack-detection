"""Safe response execution contracts.

Phase 7 intentionally implements a dry-run containment executor.
The policy engine decides what should happen; this module is responsible
only for executing an already-approved response action.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


ExecutionStatus = Literal[
    "skipped",
    "pending_approval",
    "executed",
]


@dataclass(frozen=True)
class ExecutionResult:
    """Result of attempting to execute a response decision."""

    status: ExecutionStatus
    action: str
    event_id: str
    reason: str
    executed: bool = False


class ResponseExecutor:
    """Execute approved response decisions safely.

    The initial implementation is deliberately dry-run. It does not
    modify firewall rules, terminate processes, disable accounts, or
    otherwise change the host/network.
    """

    def execute(
        self,
        *,
        event_id: str,
        action: str,
        requires_approval: bool,
        approved: bool = False,
    ) -> ExecutionResult:
        if action == "observe":
            return ExecutionResult(
                status="skipped",
                action=action,
                event_id=event_id,
                reason="observe action does not require execution",
            )

        if action == "notify":
            return ExecutionResult(
                status="skipped",
                action=action,
                event_id=event_id,
                reason="notification execution is not enabled in Phase 7",
            )

        if action != "contain":
            raise ValueError(f"unsupported response action: {action}")

        if requires_approval and not approved:
            return ExecutionResult(
                status="pending_approval",
                action=action,
                event_id=event_id,
                reason="containment requires explicit approval",
            )

        return ExecutionResult(
            status="executed",
            action=action,
            event_id=event_id,
            reason="approved containment executed in dry-run mode",
            executed=True,
        )
