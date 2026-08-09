"""Tests for the AttackDetector facade."""
import unittest
from analyzer.detector import AttackDetector


class TestAttackDetector(unittest.TestCase):

    def setUp(self):
        # Low threshold so 2 failures trigger brute-force in tests
        self.detector = AttackDetector(bruteforce_threshold=2)

    def _entry(self, ip, path, status, raw=""):
        return {"host": ip, "ip": ip, "path": path, "status": status, "raw": raw or f'{ip} - - [28/Oct/2025:10:00:00 +0000] "GET {path} HTTP/1.1" {status} 0 "-" "-"'}

    def test_bruteforce_detection(self):
        logs = [
            self._entry("10.0.0.2", "/login", 401),
            self._entry("10.0.0.2", "/login", 401),
            self._entry("10.0.0.2", "/login", 200),
        ]
        alerts = self.detector.detect(logs)
        self.assertTrue(any(a.get("type") == "Brute Force" for a in alerts))

    def test_sql_injection_detection(self):
        logs = [
            self._entry("127.0.0.1", "/search", 200,
                        raw="127.0.0.1 - - [28/Oct/2025:10:00:00 +0000] \"GET /search?q=' OR 1=1-- HTTP/1.1\" 200 0 \"-\" \"-\"")
        ]
        alerts = self.detector.detect(logs)
        self.assertTrue(any(a.get("type") == "SQL Injection" for a in alerts))

    def test_xss_detection(self):
        logs = [
            self._entry("127.0.0.1", "/comment", 200,
                        raw="127.0.0.1 - - [28/Oct/2025:10:00:00 +0000] \"GET /comment?msg=<script>alert(1)</script> HTTP/1.1\" 200 0 \"-\" \"-\"")
        ]
        alerts = self.detector.detect(logs)
        self.assertTrue(any(a.get("type") == "XSS" for a in alerts))

    def test_no_false_positive_on_clean_log(self):
        logs = [self._entry("1.2.3.4", "/index.html", 200)]
        alerts = self.detector.detect(logs)
        self.assertEqual(alerts, [])

    def test_percent_encoded_sqli_detected(self):
        logs = [
            self._entry("192.168.1.5", "/login.php", 403,
                        raw="192.168.1.5 - - [30/Oct/2025:11:45:34 +0000] \"GET /login.php?id=1%20OR%201=1 HTTP/1.1\" 403 321 \"-\" \"-\"")
        ]
        alerts = self.detector.detect(logs)
        self.assertTrue(any(a.get("type") == "SQL Injection" for a in alerts))


if __name__ == "__main__":
    unittest.main()
