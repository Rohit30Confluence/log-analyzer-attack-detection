import unittest
from analyzer.detector import AttackDetector

class TestAttackDetector(unittest.TestCase):

    def setUp(self):
        self.detector = AttackDetector()

    def test_bruteforce_detection(self):
        logs = [
            {"ip": "10.0.0.2", "path": "/login", "status": 401},
            {"ip": "10.0.0.2", "path": "/login", "status": 401},
            {"ip": "10.0.0.2", "path": "/login", "status": 200},
        ]
        alerts = self.detector.detect(logs)
        self.assertTrue(any("Brute Force" in a["type"] for a in alerts))

    def test_sql_injection_detection(self):
        logs = [
            {"ip": "127.0.0.1", "path": "/search?q=' OR 1=1--", "status": 200}
        ]
        alerts = self.detector.detect(logs)
        self.assertTrue(any("SQL Injection" in a["type"] for a in alerts))

    def test_xss_detection(self):
        logs = [
            {"ip": "127.0.0.1", "path": "/comment?msg=<script>alert(1)</script>", "status": 200}
        ]
        alerts = self.detector.detect(logs)
        self.assertTrue(any("XSS" in a["type"] for a in alerts))

if __name__ == "__main__":
    unittest.main()
