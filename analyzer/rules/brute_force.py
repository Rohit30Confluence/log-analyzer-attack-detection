"""
Brute Force Detection Rule

Detects repeated failed requests (HTTP 401 or 403) from the same IP
against any endpoint.

Two interfaces:
  analyze(log_line: str)  — single raw log line (streaming)
  detect(logs: list)      — batch of parsed dicts from analyzer.parser
"""
from __future__ import annotations
from collections import defaultdict
from typing import List, Dict, Any, Optional


class BruteForceDetector:
    def __init__(self, threshold: int = 5):
        self.threshold = threshold
        self._stream_failures: Dict[str, int] = defaultdict(int)

    # ------------------------------------------------------------------
    # Streaming interface
    # ------------------------------------------------------------------
    def analyze(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Analyse a single raw log line. Returns alert dict or None."""
        has_failure = (
            " 401 " in log_line or log_line.endswith(" 401")
            or " 403 " in log_line or log_line.endswith(" 403")
        )
        if not has_failure:
            return None
        parts = log_line.split()
        if not parts:
            return None
        ip = parts[0]
        self._stream_failures[ip] += 1
        if self._stream_failures[ip] >= self.threshold:
            return {
                "ip": ip,
                "type": "Brute Force",
                "attack_type": "Brute Force",
                "message": f"Detected {self._stream_failures[ip]} failed requests from {ip}",
            }
        return None

    # ------------------------------------------------------------------
    # Batch interface
    # ------------------------------------------------------------------
    def detect(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyse a batch of parsed log dicts.
        Each dict must have: ip/host (str), status (int), path (str).
        Returns list of alert dicts.
        """
        ip_failures: Dict[str, int] = defaultdict(int)
        ip_sample_path: Dict[str, str] = {}

        for entry in logs:
            ip = entry.get("ip") or entry.get("host") or ""
            status = entry.get("status", 0)
            path = entry.get("path") or ""
            if status in (401, 403):
                ip_failures[ip] += 1
                ip_sample_path.setdefault(ip, path)

        alerts = []
        for ip, count in ip_failures.items():
            if count >= self.threshold:
                alerts.append({
                    "ip": ip,
                    "type": "Brute Force",
                    "attack_type": "Brute Force",
                    "fail_count": count,
                    "sample_path": ip_sample_path.get(ip, ""),
                    "message": f"Detected {count} failed requests (401/403) from {ip}",
                })
        return alerts
