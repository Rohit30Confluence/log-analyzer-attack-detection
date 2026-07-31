"""CLI entry point for log analysis, attack detection, and visualization."""
import argparse
import sys
from pathlib import Path

from analyzer.parser import parse_file
from analyzer.rules.brute_force import BruteForceDetector
from analyzer.rules.sql_injection import SQLInjectionDetector
from analyzer.rules.xss import XSSDetector
from analyzer.anomaly_detector import AnomalyDetector
from scripts.visualize_results import visualize_results


def main():
    parser = argparse.ArgumentParser(
        description="Unified CLI for log analysis, attack detection, and visualization"
    )
    parser.add_argument("--input", required=True, help="Path to Apache access log file")
    parser.add_argument("--analyze", action="store_true", help="Run attack detection")
    parser.add_argument("--visualize", action="store_true", help="Visualize attack trends")
    args = parser.parse_args()

    log_path = Path(args.input)
    if not log_path.exists():
        print(f"[!] File not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    logs = list(parse_file(log_path))
    print(f"[+] Parsed {len(logs)} log entries.")

    results: dict = {}

    if args.analyze:
        print("[*] Running attack detection...")

        # Brute Force — batch mode over parsed dicts
        bf_detector = BruteForceDetector()
        bf_alerts = bf_detector.detect(logs)
        results["Brute Force"] = bf_alerts
        print(f"  -> Brute Force: {len(bf_alerts)} suspicious entries")

        # SQL Injection + XSS — per raw log line
        sqli_detector = SQLInjectionDetector()
        xss_detector = XSSDetector()
        sqli_alerts, xss_alerts = [], []

        for entry in logs:
            raw = entry.get("raw") or ""
            host = entry.get("host", "")

            sqli = sqli_detector.analyze(raw)
            if sqli:
                sqli["host"] = host
                sqli_alerts.append(sqli)

            xss = xss_detector.analyze(raw)
            if xss:
                xss["host"] = host
                xss_alerts.append(xss)

        results["SQL Injection"] = sqli_alerts
        results["XSS"] = xss_alerts
        print(f"  -> SQL Injection: {len(sqli_alerts)} suspicious entries")
        print(f"  -> XSS: {len(xss_alerts)} suspicious entries")

        # Anomaly detection
        raw_lines = [e.get("raw", "") for e in logs if e.get("raw")]
        anomaly = AnomalyDetector()
        anomaly.fit(raw_lines)
        anomalies = anomaly.detect()
        results["Anomaly"] = anomalies
        print(f"  -> Anomaly: {len(anomalies)} suspicious IPs")

    if args.visualize:
        print("[*] Visualizing results...")
        visualize_results(results)


if __name__ == "__main__":
    main()
