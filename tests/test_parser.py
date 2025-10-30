import unittest
from analyzer.parser import ApacheLogParser

class TestApacheLogParser(unittest.TestCase):

    def setUp(self):
        self.parser = ApacheLogParser()

    def test_valid_log_line(self):
        log_line = '192.168.0.10 - - [28/Oct/2025:10:45:32 +0000] "GET /login HTTP/1.1" 200 512'
        result = self.parser.parse_line(log_line)
        self.assertIsNotNone(result)
        self.assertEqual(result["ip"], "192.168.0.10")
        self.assertEqual(result["method"], "GET")
        self.assertEqual(result["status"], 200)

    def test_malformed_log_line(self):
        bad_line = 'broken log entry without fields'
        result = self.parser.parse_line(bad_line)
        self.assertIsNone(result)

if __name__ == "__main__":
    unittest.main()
