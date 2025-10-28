"""
Cross-Site Scripting (XSS) Detection Rule
Detects script injection attempts in URLs or query parameters.
"""

import re

XSS_PATTERNS = [
    r"<script.*?>.*?</script>",
    r"onerror=.*?=",
    r"alert\(.*?\)"
]

class XSSDetector:
    def analyze(self, log_line):
        for pattern in XSS_PATTERNS:
            if re.search(pattern, log_line, re.IGNORECASE):
                return {
                    "attack_type": "XSS",
                    "pattern": pattern,
                    "log_snippet": log_line.strip()[:120]
                }
        return None
