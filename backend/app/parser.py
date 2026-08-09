"""
Apache Combined Log Format parser.

Stream-parses log lines into typed dict records. No external deps.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) '                 # %h
    r'(?P<ident>\S+) '              # %l
    r'(?P<authuser>\S+) '           # %u
    r'\[(?P<date>[^\]]+)\] '        # %t
    r'"(?P<request>[^"]*)" '        # "%r"
    r'(?P<status>\d{3}) '           # %>s
    r'(?P<bytes>\S+) '              # %b
    r'"(?P<referer>[^"]*)" '        # "%{Referer}i"
    r'"(?P<useragent>[^"]*)"'       # "%{User-agent}i"
)

DATE_FMT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_date(raw: str) -> Optional[datetime]:
    try:
        return datetime.strptime(raw, DATE_FMT)
    except (ValueError, TypeError):
        return None


def _split_request(req: str) -> Dict[str, Optional[str]]:
    parts = req.split()
    if len(parts) >= 3:
        return {"method": parts[0], "path": parts[1], "protocol": parts[2]}
    if len(parts) == 2:
        return {"method": parts[0], "path": parts[1], "protocol": None}
    return {"method": None, "path": parts[0] if parts else None, "protocol": None}


def parse_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse one CLF/combined log line. Returns None on malformed input."""
    line = line.strip()
    if not line:
        return None
    m = LOG_PATTERN.match(line)
    if not m:
        return None
    gd = m.groupdict()
    nr = _split_request(gd.get("request") or "")
    bytes_sent = gd.get("bytes")
    try:
        status = int(gd["status"])
    except (TypeError, ValueError):
        status = None
    return {
        "ip": gd.get("ip"),
        "ident": gd.get("ident"),
        "authuser": gd.get("authuser"),
        "time": _parse_date(gd.get("date", "")),
        "raw_time": gd.get("date"),
        "method": nr["method"],
        "path": nr["path"],
        "protocol": nr["protocol"],
        "status": status,
        "bytes": None if bytes_sent == "-" else _safe_int(bytes_sent),
        "referer": gd.get("referer"),
        "useragent": gd.get("useragent"),
        "raw": line,
    }


def _safe_int(v: Optional[str]) -> Optional[int]:
    try:
        return int(v) if v is not None else None
    except ValueError:
        return None


def parse_text(text: str) -> Iterator[Dict[str, Any]]:
    for line in text.splitlines():
        rec = parse_line(line)
        if rec:
            yield rec


def parse_file(path: Path | str, max_lines: Optional[int] = None) -> Iterator[Dict[str, Any]]:
    p = Path(path)
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh):
            if max_lines is not None and i >= max_lines:
                break
            rec = parse_line(line)
            if rec:
                yield rec
