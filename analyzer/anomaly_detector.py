import re
from collections import defaultdict, Counter
import numpy as np

class AnomalyDetector:
    def __init__(self, threshold=2.5):
        self.threshold = threshold  # Z-score threshold
        self.ip_request_count = Counter()
        self.status_code_map = defaultdict(list)
    
    def fit(self, log_lines):
        for line in log_lines:
            match = re.match(r'(\S+) .*"(\S+) (\S+) .*" (\d+)', line)
            if not match:
                continue
            ip, method, path, status = match.groups()
            self.ip_request_count[ip] += 1
            self.status_code_map[ip].append(int(status))
    
    def detect(self):
        counts = np.array(list(self.ip_request_count.values()))
        mean, std = np.mean(counts), np.std(counts)
        if std == 0:
            return []
        anomalies = []
        for ip, count in self.ip_request_count.items():
            z = (count - mean) / std
            if z > self.threshold:
                anomalies.append({
                    "ip": ip,
                    "score": round(z, 2),
                    "reason": "Unusually high request volume"
                })
        return anomalies
