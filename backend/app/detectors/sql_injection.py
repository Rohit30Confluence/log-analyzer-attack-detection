"""SQL injection: signature matching against the request path/query, decoded."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import unquote

# Matched only against the decoded PATH (not the whole raw line) to avoid
# false-positiving on unrelated '#' or '--' in referrers/user-agents.
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
        m = _COMPILED.search(decoded)
        if not m:
            return None
        return {
            "type": "SQL Injection",
            "ip": entry.get("ip"),
            "detail": f"Suspicious query on {decoded[:120]}",
            "pattern": m.group(0),
            "severity": "high",
        }
