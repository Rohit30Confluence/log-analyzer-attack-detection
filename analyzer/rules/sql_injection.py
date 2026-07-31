"""
SQL Injection Detection Rule

Identifies suspicious SQL keywords and patterns in query parameters or URIs.
Percent-encoded payloads are decoded before matching.
"""
from __future__ import annotations
import re
from urllib.parse import unquote
from typing import Optional, Dict, Any

SQLI_PATTERNS = [
    r"(\bUNION\b.*\bSELECT\b)",
    r"(\bDROP\s+TABLE\b)",
    r"(\bOR\s+1\s*=\s*1\b)",
    r"(\bSELECT\s+\*\s+FROM\b)",
    r"(\bSELECT\b.*\bFROM\b)",
    r"(-{2,}|#|/\*)",
    r"(\bINSERT\s+INTO\b)",
    r"(\bDELETE\s+FROM\b)",
    r"(\bEXEC\s*\()",
]

_COMPILED = re.compile("|".join(SQLI_PATTERNS), re.IGNORECASE)


class SQLInjectionDetector:
    def analyze(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Return alert dict if SQLi pattern found, else None."""
        decoded = unquote(log_line)
        m = _COMPILED.search(decoded)
        if m:
            return {
                "attack_type": "SQL Injection",
                "type": "SQL Injection",
                "pattern": m.group(0),
                "log_snippet": decoded.strip()[:120],
            }
        return None
