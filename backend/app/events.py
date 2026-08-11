"""Canonical security-event contract used by every detector and API path."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4


EVENT_VERSION = "1.0"


@dataclass
class SecurityEvent:
    event_type: str
    detector: str
    rule_id: str
    severity: str
    confidence: float
    source_ip: Optional[str] = None
    target: Optional[str] = None
    evidence: Optional[str] = None
    detail: Optional[str] = None
    pattern: Optional[str] = None
    observed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    event_id: str = field(default_factory=lambda: str(uuid4()))
    event_version: str = EVENT_VERSION
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Response/lifecycle state.
    status: str = "open"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    occurrence_count: int = 1
    correlation_id: Optional[str] = None
    resolution: Optional[str] = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")

        if self.severity not in {"low", "medium", "high", "critical"}:
            raise ValueError(f"invalid severity: {self.severity}")

        if not self.event_type:
            raise ValueError("event_type is required")

        if not self.detector:
            raise ValueError("detector is required")

        if not self.rule_id:
            raise ValueError("rule_id is required")

        from .lifecycle import STATUSES

        if self.status not in STATUSES:
            raise ValueError(f"invalid status: {self.status}")

        if self.occurrence_count < 1:
            raise ValueError("occurrence_count must be at least 1")

        if self.first_seen is None:
            self.first_seen = self.observed_at

        if self.last_seen is None:
            self.last_seen = self.observed_at

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize the canonical security event while preserving the legacy
        alert fields consumed by the existing API/dashboard contract.

        Canonical fields remain authoritative. Compatibility aliases are
        presentation/API fields and must not be used as the internal event
        model.
        """
        data = asdict(self)

        # Legacy API/dashboard compatibility.
        data["type"] = self.event_type
        data["ip"] = self.source_ip
        data["pattern"] = self.pattern or self.evidence

        return data
