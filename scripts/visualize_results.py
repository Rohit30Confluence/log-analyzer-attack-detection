"""Visualization helpers for attack detection results."""
from __future__ import annotations
import matplotlib
matplotlib.use("Agg")  # non-interactive backend for CI / servers
import matplotlib.pyplot as plt
from typing import Dict, List, Any


def visualize_results(
    results: Dict[str, List[Any]],
    output: str = "attack_trends.png",
) -> None:
    """
    Render a bar chart of detected attack types and save to disk.

    Args:
        results: dict mapping attack-type name -> list of alert dicts.
        output:  PNG file path to write.
    """
    counts = {name: len(alerts) for name, alerts in results.items()}
    if not counts:
        print("[!] No results to visualize.")
        return

    plt.figure(figsize=(8, 4))
    plt.bar(counts.keys(), counts.values(), color="#2563eb")
    plt.title("Detected Attack Patterns")
    plt.xlabel("Attack Type")
    plt.ylabel("Count")
    plt.tight_layout()

    try:
        plt.savefig(output)
        print(f"[+] Chart saved to {output}")
    except Exception as e:
        print(f"[!] Could not save chart: {e}")
    finally:
        plt.close()


# Legacy alias
visualize_attack_trends = visualize_results


if __name__ == "__main__":
    sample = {
        "Brute Force": [{}, {}],
        "SQL Injection": [{}, {}, {}],
        "XSS": [{}],
        "Anomaly": [{}],
    }
    visualize_results(sample)
