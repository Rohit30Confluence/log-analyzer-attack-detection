# backend/main.py
import os
import json
from typing import Dict, List
from collections import defaultdict, Counter

import redis
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# --- Detection helper functions  ---
import re

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

# --- FastAPI app and Redis client ---
app = FastAPI(title="Log Analyzer API (Realtime)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

REDIS_URL = os.getenv("REDIS_URL", "")
if not REDIS_URL:
    # allow running without Redis for dev, but warn
    redis_client = None
else:
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)

class AnalyzeResponse(BaseModel):
    sql_injection: List[Dict]
    xss: List[Dict]
    brute_force_candidates: List[Dict]
    summary: Dict

@app.get("/ping")
def ping():
    return {"status": "ok", "service": "log-analyzer-api"}

@app.get("/health")
def health():
    try:
        if redis_client:
            redis_client.ping()
        return {"status": "ok", "redis": bool(redis_client)}
    except Exception as e:
        return {"status": "error", "detail": str(e)}

@app.post("/ingest")
async def ingest_log(raw: str = Form(None), file: UploadFile = File(None), payload: dict = None):
    """
    Accept either:
    - `raw` form field (single log line)
    - file upload (text/plain) with many lines
    - JSON body (application/json) as payload
    This endpoint queues the raw text into Redis list "logs_stream".
    """
    # Normalize input into a JSON object
    if payload:
        entry = payload
    elif file:
        content = (await file.read()).decode(errors="ignore")
        entry = {"raw": content}
    elif raw:
        entry = {"raw": raw}
    else:
        raise HTTPException(status_code=400, detail="No input provided. Use JSON body, file upload or raw form.")

    # Add optional metadata fields
    if "time" not in entry:
        entry["time"] = entry.get("time") or None

    # If redis is configured, push to queue
    if redis_client:
        try:
            redis_client.lpush("logs_stream", json.dumps(entry))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Redis push failed: {e}")
        return {"queued": True}
    else:
        # fallback: analyze inline (not recommended for production)
        text = entry.get("raw", "")
        sigs = detect_signatures(text)
        parsed = list(parse_lines(text))
        brutef = detect_bruteforce_from_parsed(parsed)
        summary = {
            "total_lines": len(text.splitlines()),
            "parsed_entries": sum(1 for p in parsed if p.get("ip")),
            "raw_matches": len(sigs["sql_injection"]) + len(sigs["xss"]),
        }
        return AnalyzeResponse(
            sql_injection=sigs["sql_injection"],
            xss=sigs["xss"],
            brute_force_candidates=brutef,
            summary=summary
        )

# Keep uvicorn bootstrapping so "python main.py" works and honors $PORT set by platforms.
if __name__ == "__main__":
    import uvicorn, os
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
