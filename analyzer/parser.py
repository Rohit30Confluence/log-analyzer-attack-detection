\"\"\"Apache combined log parser.

Stream parses Common/Combined Log Format lines into typed dict records.
\"\"\"
from __future__ import annotations
import re
from datetime import datetime
from typing import Iterator, Optional, Dict, Any, Iterable
from pathlib import Path

# Regex for combined log format -- named groups for clarity
LOG_PATTERN = re.compile(
    r'(?P<host>\\S+) '                 # host %h
    r'(?P<ident>\\S+) '                # ident %l
    r'(?P<authuser>\\S+) '             # authuser %u
    r'\\[(?P<date>[^\\]]+)\\] '        # date %t
    r'\"(?P<request>[^\"]*)\" '        # request \"%r\"
    r'(?P<status>\\d{3}) '             # status %>s
    r'(?P<bytes>\\S+) '                # bytes %b
    r'\"(?P<referer>[^\"]*)\" '        # referer \"%{Referer}i\"
    r'\"(?P<useragent>[^\"]*)\"'       # user-agent \"%{User-agent}i\"
)

DATE_FMT = \"%d/%b/%Y:%H:%M:%S %z\"  # example: 10/Oct/2000:13:55:36 -0700


def _parse_date(raw: str) -> Optional[datetime]:
    try:
        return datetime.strptime(raw, DATE_FMT)
    except Exception:
        return None


def _normalize_request(req: str) -> Dict[str, Optional[str]]:
    method = path = protocol = None
    if not req:
        return {"method": None, "path": None, "protocol": None}
    parts = req.split()
    if len(parts) >= 3:
        method, path, protocol = parts[0], parts[1], parts[2]
    elif len(parts) == 2:
        method, path = parts[0], parts[1]
    else:
        # single token request (rare), keep it as path
        path = parts[0] if parts else None
    return {"method": method, "path": path, "protocol": protocol}


def parse_line(line: str) -> Optional[Dict[str, Any]]:
    \"\"\"Parse a single CLF/combined log line into a dict or return None on failure.\"\"\"
    m = LOG_PATTERN.match(line.strip())
    if not m:
        return None
    gd = m.groupdict()
    dt = _parse_date(gd.get(\"date\", \"\"))
    req = gd.get(\"request\") or \"\"
    nr = _normalize_request(req)
    bytes_sent = gd.get(\"bytes\")
    return {
        \"host\": gd.get(\"host\"),
        \"ident\": gd.get(\"ident\"),
        \"authuser\": gd.get(\"authuser\"),
        \"time\": dt,
        \"raw_time\": gd.get(\"date\"),
        \"method\": nr.get(\"method\"),
        \"path\": nr.get(\"path\"),
        \"protocol\": nr.get(\"protocol\"),
        \"status\": int(gd.get(\"status\")) if gd.get(\"status\") else None,
        \"bytes\": None if bytes_sent == \"-\" else int(bytes_sent),
        \"referer\": gd.get(\"referer\"),
        \"useragent\": gd.get(\"useragent\"),
        \"raw\": line.strip(),
    }


def parse_file(path: Path | str, max_lines: Optional[int] = None) -> Iterator[Dict[str, Any]]:
    \"\"\"Stream parse a log file yielding parsed records.\"\"\"
    p = Path(path)
    with p.open(\"r\", encoding=\"utf-8\", errors=\"replace\") as fh:
        for i, line in enumerate(fh):
            if max_lines is not None and i >= max_lines:
                break
            rec = parse_line(line)
            if rec:
                yield rec
