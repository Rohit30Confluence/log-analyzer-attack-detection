"""Brute-force authentication detection."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List

from ..events import SecurityEvent
from .rules import BRUTE_FORCE


class BruteForceDetector:
    def __init__(self, threshold: int = 5):
        self.threshold = threshold

    def detect(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        fails: Dict[str, int] = defaultdict(int)
        sample_path: Dict[str, str] = {}

        for entry in logs:
            if entry.get("status") in (401, 403):
                ip = entry.get("ip") or "unknown"
                fails[ip] += 1
                sample_path.setdefault(ip, entry.get("path") or "")

        events = []

        for ip, count in fails.items():
            if count < self.threshold:
                continue

            severity = "critical" if count >= self.threshold * 3 else "high"
            target = sample_path.get(ip, "")

            event = SecurityEvent(
                event_type="Brute Force",
                detector="BruteForceDetector",
                rule_id=BRUTE_FORCE,
                severity=severity,
                confidence=min(1.0, 0.75 + (count - self.threshold) * 0.05),
                source_ip=ip,
                target=target,
                evidence=f"{count} failed authentication attempts using HTTP 401/403",
                detail=f"{count} failed auth attempts (401/403) against {target}",
                metadata={
                    "threshold": self.threshold,
                    "failed_attempts": count,
                    "status_codes": [401, 403],
                },
            )

            events.append(event.to_dict())

        return events
