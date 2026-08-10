"""
Volume anomaly detection.

Unlike a naive single-batch z-score (which only compares IPs against each
other within one call and forgets everything afterward), this compares each
IP's current request count against ITS OWN recent history, pulled from
SQLite. That's a real, if simple, time-series baseline instead of a
same-batch heuristic.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List

import numpy as np

from .. import db


class AnomalyDetector:
    def __init__(self, threshold: float = 2.5, min_history: int = 3):
        self.threshold = threshold
        self.min_history = min_history

    def detect(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        counts = Counter(e.get("ip") or "unknown" for e in logs)

        # Persist this batch into the rolling history so future calls have
        # a real baseline to compare against.
        db.record_ip_traffic(dict(counts))

        alerts = []
        for ip, count in counts.items():
            history = db.get_ip_history(ip, windows=20)
            if len(history) < self.min_history:
                continue  # not enough history yet to call this an anomaly
            arr = np.array(history[:-1]) if len(history) > 1 else np.array(history)
            mean, std = arr.mean(), arr.std()
            if std == 0:
                continue
            z = (count - mean) / std
            if z > self.threshold:
                alerts.append({
                    "type": "Traffic Anomaly",
                    "ip": ip,
                    "detail": f"{count} requests this window vs baseline mean {mean:.1f} (z={z:.2f})",
                    "pattern": None,
                    "severity": "medium",
                })
        return alerts
