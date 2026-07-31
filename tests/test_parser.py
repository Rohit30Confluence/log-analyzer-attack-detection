"""Tests for analyzer.parser module."""
import unittest
from analyzer.parser import parse_line


class TestParser(unittest.TestCase):

    def test_valid_combined_log_line(self):
        line = (
            '192.168.0.10 - - [28/Oct/2025:10:45:32 +0000] '
            '"GET /login HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
        )
        result = parse_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["host"], "192.168.0.10")
        self.assertEqual(result["method"], "GET")
        self.assertEqual(result["path"], "/login")
        self.assertEqual(result["status"], 200)

    def test_valid_clf_line_with_auth_failure(self):
        line = (
            '10.0.0.1 - frank [28/Oct/2025:10:00:00 +0000] '
            '"POST /admin HTTP/1.1" 401 0 "-" "-"'
        )
        result = parse_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["host"], "10.0.0.1")
        self.assertEqual(result["status"], 401)

    def test_malformed_log_line_returns_none(self):
        result = parse_line("broken log entry without fields")
        self.assertIsNone(result)

    def test_raw_field_preserved(self):
        line = (
            '127.0.0.1 - - [28/Oct/2025:10:45:32 +0000] '
            '"GET /index.html HTTP/1.1" 200 1234 "-" "-"'
        )
        result = parse_line(line)
        self.assertIsNotNone(result)
        self.assertIn("raw", result)
        self.assertEqual(result["raw"], line.strip())

    def test_percent_encoded_path_preserved(self):
        line = (
            '192.168.1.5 - - [30/Oct/2025:11:45:34 +0000] '
            '"GET /login.php?id=1%20OR%201=1 HTTP/1.1" 403 321 "-" "-"'
        )
        result = parse_line(line)
        self.assertIsNotNone(result)
        self.assertIn("%20", result["path"])


if __name__ == "__main__":
    unittest.main()
