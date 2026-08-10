"""Brute force: repeated 401/403 from one IP within a batch/window."""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List


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

        alerts = []
        for ip, count in fails.items():
            if count >= self.threshold:
                alerts.append({
                    "type": "Brute Force",
                    "ip": ip,
                    "detail": f"{count} failed auth attempts (401/403) against {sample_path.get(ip, '')}",
                    "pattern": None,
                    "severity": "critical" if count >= self.threshold * 3 else "high",
                })
        return alerts
