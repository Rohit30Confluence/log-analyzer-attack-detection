"""
Volume anomaly detection using the persistent SQLite traffic baseline.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List

import numpy as np

from .. import db
from ..events import SecurityEvent
from .rules import TRAFFIC_ANOMALY


class AnomalyDetector:
    def __init__(self, threshold: float = 2.5, min_history: int = 3):
        self.threshold = threshold
        self.min_history = min_history

    def detect(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        counts = Counter(e.get("ip") or "unknown" for e in logs)

        db.record_ip_traffic(dict(counts))

        events = []

        for ip, count in counts.items():
            history = db.get_ip_history(ip, windows=20)

            if len(history) < self.min_history:
                continue

            baseline = history[:-1] if len(history) > 1 else history
            arr = np.array(baseline)

            mean = arr.mean()
            std = arr.std()

            if std == 0:
                continue

            z = (count - mean) / std

            if z <= self.threshold:
                continue

            severity = "high" if z >= self.threshold * 2 else "medium"

            event = SecurityEvent(
                event_type="Traffic Anomaly",
                detector="AnomalyDetector",
                rule_id=TRAFFIC_ANOMALY,
                severity=severity,
                confidence=min(1.0, 0.70 + min(z / 10.0, 0.25)),
                source_ip=ip,
                evidence=f"{count} requests in current window; baseline mean {mean:.1f}; z-score {z:.2f}",
                detail=(
                    f"{count} requests this window vs baseline "
                    f"mean {mean:.1f} (z={z:.2f})"
                ),
                metadata={
                    "current_count": count,
                    "baseline_mean": round(float(mean), 3),
                    "baseline_stddev": round(float(std), 3),
                    "z_score": round(float(z), 3),
                    "threshold": self.threshold,
                },
            )

            events.append(event.to_dict())

        return events
