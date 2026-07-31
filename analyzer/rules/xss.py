"""
Cross-Site Scripting (XSS) Detection Rule

Detects script injection attempts in URLs or query parameters.
Percent-encoded payloads are decoded before matching.
"""
from __future__ import annotations
import re
from urllib.parse import unquote
from typing import Optional, Dict, Any

XSS_PATTERNS = [
    r"<script[\s\S]*?>",
    r"</script>",
    r"onerror\s*=",
    r"onload\s*=",
    r"onclick\s*=",
    r"alert\s*\(",
    r"javascript\s*:",
    r"<iframe[\s\S]*?>",
    r"<img[^>]+on\w+\s*=",
    r"document\.cookie",
    r"eval\s*\(",
]

_COMPILED = re.compile("|".join(XSS_PATTERNS), re.IGNORECASE | re.DOTALL)


class XSSDetector:
    def analyze(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Return alert dict if XSS pattern found, else None."""
        decoded = unquote(log_line)
        m = _COMPILED.search(decoded)
        if m:
            return {
                "attack_type": "XSS",
                "type": "XSS",
                "pattern": m.group(0),
                "log_snippet": decoded.strip()[:120],
            }
        return None
