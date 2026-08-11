"""SQL injection signature detection."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional
from urllib.parse import unquote

from ..events import SecurityEvent
from .rules import SQL_INJECTION


SQLI_PATTERNS = [
    r"\bunion\b[\s\S]{0,40}\bselect\b",
    r"\bdrop\s+table\b",
    r"\bor\s+1\s*=\s*1\b",
    r"\bselect\b[\s\S]{0,40}\bfrom\b",
    r"\binsert\s+into\b",
    r"\bdelete\s+from\b",
    r"\bexec\s*\(",
    r"';?\s*--",
    r"/\*[\s\S]*?\*/",
]

_COMPILED = re.compile("|".join(SQLI_PATTERNS), re.IGNORECASE)


class SQLInjectionDetector:
    def analyze(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        path = entry.get("path") or ""
        decoded = unquote(path)
        match = _COMPILED.search(decoded)

        if not match:
            return None

        evidence = match.group(0)

        return SecurityEvent(
            event_type="SQL Injection",
            detector="SQLInjectionDetector",
            rule_id=SQL_INJECTION,
            severity="high",
            confidence=0.92,
            source_ip=entry.get("ip"),
            target=decoded[:120],
            evidence=evidence[:120],
            detail=f"Suspicious query on {decoded[:120]}",
            pattern=evidence[:120],
        ).to_dict()
