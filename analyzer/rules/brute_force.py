"""
Brute Force Detection Rule
Detects repeated failed login attempts from the same IP within a short time frame.
"""

from collections import defaultdict

class BruteForceDetector:
    def __init__(self, threshold=5):
        self.failed_attempts = defaultdict(int)
        self.threshold = threshold

    def analyze(self, log_line):
        if "POST /login" in log_line and '401' in log_line:
            ip = log_line.split()[0]
            self.failed_attempts[ip] += 1
            if self.failed_attempts[ip] >= self.threshold:
                return {
                    "ip": ip,
                    "attack_type": "Brute Force",
                    "message": f"Detected {self.failed_attempts[ip]} failed logins from {ip}"
                }
        return None
