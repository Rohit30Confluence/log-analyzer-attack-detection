"""Cross-site scripting signature detection."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional
from urllib.parse import unquote

from ..events import SecurityEvent
from .rules import XSS


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
        match = _COMPILED.search(decoded)

        if not match:
            return None

        evidence = match.group(0)

        return SecurityEvent(
            event_type="XSS",
            detector="XSSDetector",
            rule_id=XSS,
            severity="high",
            confidence=0.94,
            source_ip=entry.get("ip"),
            target=decoded[:120],
            evidence=evidence[:120],
            detail=f"Suspicious payload on {decoded[:120]}",
            pattern=evidence[:120],
        ).to_dict()
