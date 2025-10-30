import argparse
from analyzer.parser.apache_log_parser import ApacheLogParser
from analyzer.rules.brute_force import BruteForceDetector
from analyzer.rules.sql_injection import SQLInjectionDetector
from analyzer.rules.xss import XSSDetector
from scripts.visualize_results import visualize_results

def main():
    parser = argparse.ArgumentParser(
        description="Unified CLI for log analysis, attack detection, and visualization"
    )

    parser.add_argument("--input", required=True, help="Path to Apache access log file")
    parser.add_argument("--analyze", action="store_true", help="Run attack detection")
    parser.add_argument("--visualize", action="store_true", help="Visualize attack trends")

    args = parser.parse_args()

    # Parse logs
    log_parser = ApacheLogParser(args.input)
    logs = log_parser.parse_logs()
    print(f"[+] Parsed {len(logs)} log entries.")

    results = {}
    if args.analyze:
        print("[*] Running attack detection...")
        detectors = {
            "Brute Force": BruteForceDetector(),
            "SQL Injection": SQLInjectionDetector(),
            "XSS": XSSDetector(),
        }

        for name, detector in detectors.items():
            detected = detector.detect(logs)
            results[name] = detected
            print(f"  -> {name}: {len(detected)} suspicious entries")

    if args.visualize:
        print("[*] Visualizing results...")
        visualize_results(results)

if __name__ == "__main__":
    main()
