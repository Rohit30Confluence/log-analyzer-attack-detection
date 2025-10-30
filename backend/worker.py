# backend/worker.py
import os
import json
import time
import redis
from main import detect_signatures, parse_lines, detect_bruteforce_from_parsed

REDIS_URL = os.getenv("REDIS_URL", "")
if not REDIS_URL:
    raise SystemExit("REDIS_URL required in env")

r = redis.from_url(REDIS_URL, decode_responses=True)

print("Log-Analyzer worker started. Listening on 'logs_stream'...")

while True:
    try:
        item = r.brpop("logs_stream", timeout=10)
        if not item:
            continue
        _, payload = item
        entry = json.loads(payload)

        text = entry.get("raw", "")
        sigs = detect_signatures(text)
        parsed = list(parse_lines(text))
        brutef = detect_bruteforce_from_parsed(parsed)

        summary = {
            "sql_injection": len(sigs["sql_injection"]),
            "xss": len(sigs["xss"]),
            "bruteforce_candidates": len(brutef)
        }

        # Simple alerting: push to another list (alerts) and print
        alert = {
            "entry": entry,
            "summary": summary,
            "detected_at": time.time()
        }
        r.lpush("alerts_stream", json.dumps(alert))

        # For now, log to stdout (visible in Render/Railway logs)
        print("ALERT:", json.dumps(alert))

    except Exception as e:
        # worker should stay alive on transient errors
        print("Worker error:", str(e))
        time.sleep(2)
