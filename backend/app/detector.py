"""AttackDetector facade — the single detection code path used by every
entry point (CLI, API, simulator). There is exactly one implementation,
unlike the old project's analyzer/ vs backend split.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .detectors.anomaly import AnomalyDetector
from .detectors.brute_force import BruteForceDetector
from .detectors.path_traversal import PathTraversalDetector
from .detectors.sql_injection import SQLInjectionDetector
from .detectors.xss import XSSDetector


class AttackDetector:
    def __init__(self, bruteforce_threshold: int = 5, anomaly_threshold: float = 2.5):
        self._bf = BruteForceDetector(threshold=bruteforce_threshold)
        self._sqli = SQLInjectionDetector()
        self._xss = XSSDetector()
        self._trav = PathTraversalDetector()
        self._anomaly = AnomalyDetector(threshold=anomaly_threshold)

    def detect(self, logs: List[Dict[str, Any]], run_anomaly: bool = True) -> List[Dict[str, Any]]:
        alerts: List[Dict[str, Any]] = []
        alerts.extend(self._bf.detect(logs))

        for entry in logs:
            for det in (self._sqli, self._xss, self._trav):
                hit = det.analyze(entry)
                if hit:
                    alerts.append(hit)

        if run_anomaly:
            alerts.extend(self._anomaly.detect(logs))

        return alerts
