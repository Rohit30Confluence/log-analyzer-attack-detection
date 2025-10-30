"""
SQL Injection Detection Rule
Identifies suspicious SQL keywords and patterns in query parameters or URIs.
"""

import re

SQLI_PATTERNS = [
    r"(\bUNION\b.*\bSELECT\b)",
    r"(\bDROP\s+TABLE\b)",
    r"(\bOR\s+1=1\b)",
    r"(\bSELECT\s+\*\s+FROM\b)"
]

class SQLInjectionDetector:
    def analyze(self, log_line):
        for pattern in SQLI_PATTERNS:
            if re.search(pattern, log_line, re.IGNORECASE):
                return {
                    "attack_type": "SQL Injection",
                    "pattern": pattern,
                    "log_snippet": log_line.strip()[:120]
                }
        return None
