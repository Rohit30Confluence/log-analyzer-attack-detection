"""XSS: script/event-handler injection signature matching, decoded, path-scoped."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import unquote

XSS_PATTERNS = [
    r"<script[\s\S]*?>",
    r"onerror\s*=",
    r"onload\s*=",
    r"onclick\s*=",
    r"javascript\s*:",
    r"<iframe[\s\S]*?>",
    r"<img[^>]+on\w+\s*=",
    r"document\.cookie",
    r"eval\s*\(",
]
_COMPILED = re.compile("|".join(XSS_PATTERNS), re.IGNORECASE | re.DOTALL)


class XSSDetector:
    def analyze(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        path = entry.get("path") or ""
        decoded = unquote(path)
        m = _COMPILED.search(decoded)
        if not m:
            return None
        return {
            "type": "XSS",
            "ip": entry.get("ip"),
            "detail": f"Suspicious payload on {decoded[:120]}",
            "pattern": m.group(0),
            "severity": "high",
        }
