"""Path traversal / local file inclusion signature matching."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional
from urllib.parse import unquote

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
        m = _COMPILED.search(decoded)
        if not m:
            return None
        return {
            "type": "Path Traversal",
            "ip": entry.get("ip"),
            "detail": f"Directory traversal / LFI attempt on {decoded[:120]}",
            "pattern": m.group(0),
            "severity": "high",
        }
