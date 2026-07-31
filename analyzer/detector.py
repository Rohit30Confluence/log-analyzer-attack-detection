"""
AttackDetector facade.

Accepts a list of parsed log dicts (as produced by analyzer.parser.parse_file)
and runs all three rule-based detectors.

Each alert dict contains at minimum:
    type  : str   — "Brute Force" | "SQL Injection" | "XSS"
    ip    : str
    detail: str
"""
from __future__ import annotations
from typing import List, Dict, Any

from analyzer.rules.brute_force import BruteForceDetector
from analyzer.rules.sql_injection import SQLInjectionDetector
from analyzer.rules.xss import XSSDetector


class AttackDetector:
    """Facade that wires all rule detectors and returns a unified alert list."""

    def __init__(self, bruteforce_threshold: int = 5):
        self._bf = BruteForceDetector(threshold=bruteforce_threshold)
        self._sqli = SQLInjectionDetector()
        self._xss = XSSDetector()

    def detect(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Run all detectors over a list of parsed log dicts.

        Each dict should have at least:
            ip / host : str
            path      : str  (URL path, may be percent-encoded)
            status    : int
            raw       : str  (original log line)

        Returns a list of alert dicts.
        """
        alerts: List[Dict[str, Any]] = []

        # Brute-force operates on the full batch
        alerts.extend(self._bf.detect(logs))

        # Signature detectors operate per-entry on the raw line
        for entry in logs:
            raw = entry.get("raw") or entry.get("path") or ""
            ip = entry.get("ip") or entry.get("host") or ""

            sqli = self._sqli.analyze(raw)
            if sqli:
                sqli["ip"] = ip
                sqli["type"] = "SQL Injection"
                alerts.append(sqli)

            xss = self._xss.analyze(raw)
            if xss:
                xss["ip"] = ip
                xss["type"] = "XSS"
                alerts.append(xss)

        return alerts
