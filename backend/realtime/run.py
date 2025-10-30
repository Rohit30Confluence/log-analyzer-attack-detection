import time
import random
import json
from datetime import datetime

from analyzer.parser import parse_log
from analyzer.detection import detect_sql_injection, detect_xss, detect_bruteforce
from analyzer.scoring import detect_anomalies, update_score

LOG_FILE = "./data/sample_access.log"  # Replace with your real-time source later

def stream_logs(logfile):
    """Simulate live log feed."""
    with open(logfile, "r") as f:
        for line in f:
            yield line.strip()
            time.sleep(random.uniform(0.2, 0.8))  # simulates live ingestion

def analyze_stream(logfile):
    print("🚀 Real-Time Log Analyzer Started")
    print("Listening for incoming logs...\n")

    for raw_line in stream_logs(logfile):
        log = parse_log(raw_line)
        if not log:
            continue

        ip = log.get("ip")
        status = int(log.get("status", 0))
        request = log.get("request", "")
        timestamp = log.get("timestamp", datetime.utcnow())

        event = "NORMAL"
        if detect_sql_injection(request):
            event = "SQLI"
        elif detect_xss(request):
            event = "XSS"
        elif detect_bruteforce(ip, status):
            event = "BRUTE"

        anomaly = detect_anomalies(ip, timestamp, status)
        score_data = update_score(ip, event)

        result = {
            "timestamp": str(timestamp),
            "ip": ip,
            "event": event,
            "anomaly": anomaly,
            "score": score_data["score"],
        }

        if score_data["score"] >= 80:
            tag = "🚨 ALERT"
        elif score_data["score"] >= 60:
            tag = "⚠️ WARNING"
        else:
            tag = "✅ OK"

        print(f"{tag} | {json.dumps(result, indent=2)}")

if __name__ == "__main__":
    analyze_stream(LOG_FILE)
