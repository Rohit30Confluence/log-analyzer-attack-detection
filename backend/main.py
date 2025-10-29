# backend/main.py
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re
from typing import List, Dict
from collections import defaultdict, Counter

app = FastAPI(title="Log Analyzer API")

# Development CORS - change before production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SQLI_PATTERNS = [
    r"(\bor\b|\band\b).*(=|like)",
    r"union(\s+all)?\s+select",
    r"(--|#|/\*).*",
    r"sleep\(\d+\)",
    r"benchmark\(",
    r"information_schema",
    r"select.*from",
]
XSS_PATTERNS = [
    r"<script\b",
    r"javascript:",
    r"onerror\s*=",
    r"<img\b.*on\w+\s*=",
    r"<iframe\b",
]

SQLI_REGEX = re.compile("|".join(SQLI_PATTERNS), re.IGNORECASE)
XSS_REGEX = re.compile("|".join(XSS_PATTERNS), re.IGNORECASE)

LOG_REGEX = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>.*?)\] "(?P<method>\S+) (?P<path>\S+) (?P<proto>HTTP/\d\.\d)" (?P<status>\d{3}) (?P<size>\S+)( "(?P<referrer>.*?)" "(?P<ua>.*?)")?'
)

def parse_lines(text: str):
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = LOG_REGEX.match(line)
        if m:
            d = m.groupdict()
            d['time'] = d.get('time')
            d['status'] = int(d.get('status') or 0)
            yield d
        else:
            yield {"raw": line}

def detect_signatures(text: str):
    findings = {"sql_injection": [], "xss": []}
    for i, line in enumerate(text.splitlines(), start=1):
        if SQLI_REGEX.search(line):
            findings["sql_injection"].append({"line": i, "content": line.strip()})
        if XSS_REGEX.search(line):
            findings["xss"].append({"line": i, "content": line.strip()})
    return findings

def detect_bruteforce_from_parsed(parsed_lines: List[Dict], threshold=10):
    ip_events = defaultdict(list)
    for d in parsed_lines:
        ip = d.get("ip")
        if not ip:
            continue
        status = d.get("status", 0)
        path = d.get("path", "")
        ip_events[ip].append({"status": status, "path": path})

    brute_candidates = []
    for ip, events in ip_events.items():
        fail_count = sum(1 for e in events if e["status"] in (401, 403))
        path_counts = Counter(e["path"] for e in events)
        top_path, top_count = (None, 0)
        if path_counts:
            top_path, top_count = path_counts.most_common(1)[0]
        if fail_count >= max(5, threshold) or top_count >= max(10, threshold):
            brute_candidates.append({
                "ip": ip,
                "fail_count": fail_count,
                "top_path": top_path,
                "top_path_count": top_count,
                "total_requests": len(events),
            })
    return brute_candidates

class AnalyzeResponse(BaseModel):
    sql_injection: List[Dict]
    xss: List[Dict]
    brute_force_candidates: List[Dict]
    summary: Dict

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_upload(file: UploadFile = File(None), raw_text: str = Form(None)):
    if file:
        content = (await file.read()).decode(errors="ignore")
    elif raw_text:
        content = raw_text
    else:
        return AnalyzeResponse(sql_injection=[], xss=[], brute_force_candidates=[], summary={})

    sigs = detect_signatures(content)
    parsed = list(parse_lines(content))
    brutef = detect_bruteforce_from_parsed(parsed)
    summary = {
        "total_lines": len(content.splitlines()),
        "parsed_entries": sum(1 for p in parsed if p.get("ip")),
        "raw_matches": len(sigs["sql_injection"]) + len(sigs["xss"]),
    }
    return AnalyzeResponse(
        sql_injection=sigs["sql_injection"],
        xss=sigs["xss"],
        brute_force_candidates=brutef,
        summary=summary
    )
