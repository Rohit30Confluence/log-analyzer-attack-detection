# backend/main.py
"""
Log Analyzer API — built on the unified analyzer/ detection engine.

Endpoints:
  GET  /ping          — liveness probe
  GET  /health        — health + Redis status
  POST /ingest        — queue raw log text into Redis (async path)
  POST /analyze       — analyze inline, return structured results (sync path)
  GET  /stream        — Server-Sent Events: stream analysis of a log file

Auth:
  All non-probe endpoints require header  X-API-Key: <value of API_KEY env var>
  Set API_KEY=  (empty) to disable auth in dev.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Any, Optional

# Ensure repo root on path so `analyzer` is importable inside Docker
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import redis
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from analyzer.parser import parse_line, parse_file
from analyzer.detector import AttackDetector
from analyzer.anomaly_detector import AnomalyDetector

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
REDIS_URL: str = os.getenv("REDIS_URL", "")
API_KEY: str = os.getenv("API_KEY", "")          # empty = auth disabled
BRUTEFORCE_THRESHOLD: int = int(os.getenv("BRUTEFORCE_THRESHOLD", "5"))
ANOMALY_THRESHOLD: float = float(os.getenv("ANOMALY_THRESHOLD", "2.5"))

_redis_client: Optional[redis.Redis] = None
if REDIS_URL:
    _redis_client = redis.from_url(REDIS_URL, decode_responses=True)

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Log Analyzer API",
    description="Apache log analysis and attack detection service.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------
def require_api_key(request: Request) -> None:
    if not API_KEY:
        return  # auth disabled
    key = request.headers.get("X-API-Key", "")
    if key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")

# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------
class Alert(BaseModel):
    type: str
    ip: Optional[str] = None
    message: Optional[str] = None
    pattern: Optional[str] = None
    log_snippet: Optional[str] = None


class AnalyzeResponse(BaseModel):
    total_lines: int
    parsed_entries: int
    alerts: List[Dict[str, Any]]
    anomalies: List[Dict[str, Any]]
    summary: Dict[str, int]

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _run_analysis(text: str) -> AnalyzeResponse:
    """Run full detection pipeline on raw log text and return structured result."""
    lines = [l for l in text.splitlines() if l.strip()]
    parsed = [r for r in (parse_line(l) for l in lines) if r]

    detector = AttackDetector(bruteforce_threshold=BRUTEFORCE_THRESHOLD)
    alerts = detector.detect(parsed)

    anomaly_det = AnomalyDetector(threshold=ANOMALY_THRESHOLD)
    anomaly_det.fit(lines)
    anomalies = anomaly_det.detect()

    summary: Dict[str, int] = {}
    for a in alerts:
        t = a.get("type", "Unknown")
        summary[t] = summary.get(t, 0) + 1
    summary["Anomaly"] = len(anomalies)

    return AnalyzeResponse(
        total_lines=len(lines),
        parsed_entries=len(parsed),
        alerts=alerts,
        anomalies=anomalies,
        summary=summary,
    )

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/ping", tags=["Health"])
def ping():
    """Liveness probe — no auth required."""
    return {"status": "ok", "service": "log-analyzer-api", "version": "2.0.0"}


@app.get("/health", tags=["Health"])
def health():
    """Health check including Redis connectivity."""
    redis_ok = False
    if _redis_client:
        try:
            _redis_client.ping()
            redis_ok = True
        except Exception:
            redis_ok = False
    return {
        "status": "ok",
        "redis_configured": bool(REDIS_URL),
        "redis_reachable": redis_ok,
        "auth_enabled": bool(API_KEY),
    }


@app.post("/ingest", tags=["Ingestion"], dependencies=[Depends(require_api_key)])
async def ingest(
    raw: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
):
    """
    Queue raw log text into Redis for async processing by the worker.
    Falls back to inline analysis if Redis is not configured.
    """
    if file:
        content = (await file.read()).decode(errors="ignore")
    elif raw:
        content = raw
    else:
        raise HTTPException(status_code=400, detail="Provide 'raw' form field or file upload.")

    entry = {"raw": content, "received_at": time.time()}

    if _redis_client:
        try:
            _redis_client.lpush("logs_stream", json.dumps(entry))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Redis push failed: {e}")
        return {"queued": True, "bytes": len(content)}

    # Fallback: inline analysis
    result = _run_analysis(content)
    return {"queued": False, "inline_result": result}


@app.post("/analyze", response_model=AnalyzeResponse, tags=["Analysis"],
          dependencies=[Depends(require_api_key)])
async def analyze(
    raw: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
):
    """
    Synchronously analyze log text and return structured detection results.
    Accepts either a 'raw' form field or a file upload.
    """
    if file:
        content = (await file.read()).decode(errors="ignore")
    elif raw:
        content = raw
    else:
        raise HTTPException(status_code=400, detail="Provide 'raw' form field or file upload.")

    return _run_analysis(content)


@app.get("/stream", tags=["Streaming"], dependencies=[Depends(require_api_key)])
def stream_log_file(log_file: str = "data/sample_access.log"):
    """
    Server-Sent Events endpoint: streams analysis of a log file line by line.
    Query param: log_file (path relative to repo root, default: data/sample_access.log)
    """
    target = _ROOT / log_file
    if not target.exists():
        raise HTTPException(status_code=404, detail=f"Log file not found: {log_file}")

    def event_generator():
        from analyzer.rules.brute_force import BruteForceDetector
        from analyzer.rules.sql_injection import SQLInjectionDetector
        from analyzer.rules.xss import XSSDetector

        bf = BruteForceDetector(threshold=BRUTEFORCE_THRESHOLD)
        sqli = SQLInjectionDetector()
        xss = XSSDetector()

        with open(target, "r", encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                entry = parse_line(raw_line)
                if not entry:
                    continue

                events = []
                if sqli.analyze(raw_line):
                    events.append("SQL Injection")
                if xss.analyze(raw_line):
                    events.append("XSS")
                if bf.analyze(raw_line):
                    events.append("Brute Force")

                payload = {
                    "ip": entry.get("host"),
                    "path": entry.get("path"),
                    "status": entry.get("status"),
                    "events": events,
                    "ts": str(entry.get("time")),
                }
                yield f"data: {json.dumps(payload)}\n\n"

        yield "data: {\"done\": true}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


# ---------------------------------------------------------------------------
# Dev entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("backend.main:app", host="0.0.0.0", port=port, reload=True)
