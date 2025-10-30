import matplotlib.pyplot as plt
from collections import Counter

def visualize_attack_trends(alerts):
    attack_types = [alert["type"] for alert in alerts]
    counts = Counter(attack_types)

    plt.figure(figsize=(8, 4))
    plt.bar(counts.keys(), counts.values())
    plt.title("Detected Attack Patterns")
    plt.xlabel("Attack Type")
    plt.ylabel("Frequency")
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    sample_alerts = [
        {"type": "Brute Force"},
        {"type": "SQL Injection"},
        {"type": "XSS"},
        {"type": "SQL Injection"},
    ]
    visualize_attack_trends(sample_alerts)
