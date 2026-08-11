"""Path traversal / local file inclusion detection."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional
from urllib.parse import unquote

from ..events import SecurityEvent
from .rules import PATH_TRAVERSAL


PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%2e%2e/",
    r"/etc/passwd",
    r"/etc/shadow",
    r"boot\.ini",
    r"win\.ini",
    r"\\windows\\system32",
]

_COMPILED = re.compile("|".join(PATTERNS), re.IGNORECASE)


class PathTraversalDetector:
    def analyze(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        path = entry.get("path") or ""
        decoded = unquote(path)
        match = _COMPILED.search(decoded)

        if not match:
            return None

        evidence = match.group(0)

        return SecurityEvent(
            event_type="Path Traversal",
            detector="PathTraversalDetector",
            rule_id=PATH_TRAVERSAL,
            severity="high",
            confidence=0.93,
            source_ip=entry.get("ip"),
            target=decoded[:120],
            evidence=evidence[:120],
            detail=f"Directory traversal / LFI attempt on {decoded[:120]}",
            pattern=evidence[:120],
        ).to_dict()
