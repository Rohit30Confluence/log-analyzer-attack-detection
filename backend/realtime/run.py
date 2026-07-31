"""Real-time streaming demo.

Streams data/sample_access.log line-by-line (simulating tail -f),
running each line through the analyzer/ detection stack.
"""
from __future__ import annotations

import json
import os
import sys
import time
import random
from datetime import datetime
from pathlib import Path

# Ensure repo root on sys.path
_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from analyzer.parser import parse_line
from analyzer.rules.brute_force import BruteForceDetector
from analyzer.rules.sql_injection import SQLInjectionDetector
from analyzer.rules.xss import XSSDetector
from analyzer.anomaly_detector import AnomalyDetector

LOG_FILE = os.getenv("LOG_FILE", str(_ROOT / "data" / "sample_access.log"))


def stream_logs(logfile: str):
    with open(logfile, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield line
            time.sleep(random.uniform(0.1, 0.4))


def analyze_stream(logfile: str) -> None:
    print("[realtime] Log Analyzer Started")
    print(f"[realtime] Streaming: {logfile}\n")

    bf = BruteForceDetector(threshold=5)
    sqli = SQLInjectionDetector()
    xss = XSSDetector()
    anomaly = AnomalyDetector(threshold=2.5)
    raw_lines = []

    for raw_line in stream_logs(logfile):
        raw_lines.append(raw_line)
        entry = parse_line(raw_line)
        if not entry:
            continue

        events = []
        if sqli.analyze(raw_line):
            events.append("SQL Injection")
        if xss.analyze(raw_line):
            events.append("XSS")
        if bf.analyze(raw_line):
            events.append("Brute Force")

        result = {
            "timestamp": str(entry.get("time") or datetime.utcnow()),
            "ip": entry.get("host"),
            "status": entry.get("status"),
            "path": entry.get("path"),
            "events": events,
        }
        tag = "[ALERT]" if events else "[OK]   "
        print(f"{tag} {json.dumps(result)}")

    print("\n[realtime] Running anomaly detection over full batch...")
    anomaly.fit(raw_lines)
    for a in anomaly.detect():
        print(f"[ANOMALY] {json.dumps(a)}")


if __name__ == "__main__":
    analyze_stream(LOG_FILE)
