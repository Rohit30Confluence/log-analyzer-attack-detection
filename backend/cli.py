#!/usr/bin/env python3
"""One-shot CLI: analyze a log file without running the server.

Usage:
    python cli.py --input data/sample_access.log
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter

from app.detector import AttackDetector
from app.parser import parse_file


def main():
    ap = argparse.ArgumentParser(description="LogSentinel — one-shot log analysis")
    ap.add_argument("--input", required=True, help="Path to an Apache combined-format log file")
    ap.add_argument("--bruteforce-threshold", type=int, default=5)
    args = ap.parse_args()

    parsed = list(parse_file(args.input))
    if not parsed:
        print(f"[!] No parseable log lines found in {args.input}", file=sys.stderr)
        sys.exit(1)

    detector = AttackDetector(bruteforce_threshold=args.bruteforce_threshold)
    # Skip the SQLite-backed anomaly check in one-shot CLI mode — it needs
    # history across runs, which a single ad-hoc file doesn't have.
    alerts = detector.detect(parsed, run_anomaly=False)

    print(f"[+] Parsed {len(parsed)} log entries.")
    print("[*] Detection results:")
    counts = Counter(a["type"] for a in alerts)
    if not counts:
        print("  -> No suspicious activity detected.")
    for atype, count in counts.items():
        print(f"  -> {atype}: {count} alert(s)")

    if alerts:
        print("\n[*] Details:")
        for a in alerts:
            print(f"  [{a['severity'].upper():8s}] {a['type']:16s} ip={a['ip']:16s} {a['detail']}")


if __name__ == "__main__":
    main()
