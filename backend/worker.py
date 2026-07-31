# backend/worker.py
"""
Redis queue consumer.

Pops entries from 'logs_stream', runs the full detection pipeline,
pushes results to 'alerts_stream', and prints to stdout.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

# Ensure repo root on sys.path
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import redis
from analyzer.parser import parse_line
from analyzer.detector import AttackDetector
from analyzer.anomaly_detector import AnomalyDetector

REDIS_URL = os.getenv("REDIS_URL", "")
BRUTEFORCE_THRESHOLD = int(os.getenv("BRUTEFORCE_THRESHOLD", "5"))
ANOMALY_THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", "2.5"))

if not REDIS_URL:
    raise SystemExit("REDIS_URL environment variable is required.")

r = redis.from_url(REDIS_URL, decode_responses=True)
print("[worker] Started. Listening on 'logs_stream'...", flush=True)

while True:
    try:
        item = r.brpop("logs_stream", timeout=10)
        if not item:
            continue

        _, payload = item
        entry = json.loads(payload)
        text: str = entry.get("raw", "")
        lines = [l for l in text.splitlines() if l.strip()]
        parsed = [rec for rec in (parse_line(l) for l in lines) if rec]

        detector = AttackDetector(bruteforce_threshold=BRUTEFORCE_THRESHOLD)
        alerts = detector.detect(parsed)

        anomaly_det = AnomalyDetector(threshold=ANOMALY_THRESHOLD)
        anomaly_det.fit(lines)
        anomalies = anomaly_det.detect()

        summary = {
            "total_lines": len(lines),
            "parsed": len(parsed),
            "alerts": len(alerts),
            "anomalies": len(anomalies),
        }

        result = {
            "received_at": entry.get("received_at"),
            "processed_at": time.time(),
            "summary": summary,
            "alerts": alerts,
            "anomalies": anomalies,
        }

        r.lpush("alerts_stream", json.dumps(result))
        # Trim alerts_stream to last 1000 entries
        r.ltrim("alerts_stream", 0, 999)

        print(f"[worker] Processed {len(lines)} lines — "
              f"{len(alerts)} alerts, {len(anomalies)} anomalies", flush=True)

    except Exception as e:
        print(f"[worker] Error: {e}", flush=True)
        time.sleep(2)
