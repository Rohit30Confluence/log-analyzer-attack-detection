"""
LogSentinel API — fully local, zero external services.

Security baseline:
- bounded request bodies and uploads
- restrictive CORS
- security response headers
- bounded database queries
- WebSocket origin validation
- controlled simulator lifecycle
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel

from fastapi import FastAPI, File, Form, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from . import db
from .detector import AttackDetector
from .parser import parse_text
from .simulator import Simulator

APP_ROOT = Path(__file__).resolve().parents[1]
STATIC_DIR = APP_ROOT / "static"

MAX_ANALYZE_BYTES = int(os.getenv("LOGSENTINEL_MAX_ANALYZE_BYTES", str(2 * 1024 * 1024)))
MAX_ALERT_LIMIT = int(os.getenv("LOGSENTINEL_MAX_ALERT_LIMIT", "200"))
MAX_RAW_LINES = int(os.getenv("LOGSENTINEL_MAX_RAW_LINES", "50000"))

ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("LOGSENTINEL_ALLOWED_ORIGINS", "http://localhost:8000").split(",")
    if origin.strip()
]


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

        return response


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init_db()
    yield


app = FastAPI(
    title="LogSentinel",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

detector = AttackDetector()


class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        origin = ws.headers.get("origin")

        if origin and origin not in ALLOWED_ORIGINS:
            await ws.close(code=1008, reason="Origin not allowed")
            return False

        await ws.accept()

        if len(self.active) >= 20:
            await ws.close(code=1013, reason="Too many connections")
            return False

        self.active.append(ws)
        return True

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, payload: dict):
        dead = []

        for ws in self.active:
            try:
                await ws.send_text(json.dumps(payload))
            except Exception:
                dead.append(ws)

        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


async def _process_lines(lines: List[str]):
    text = "\n".join(lines)
    parsed = list(parse_text(text))
    alerts = detector.detect(parsed)

    saved = db.save_alerts(alerts) if alerts else []

    if saved:
        await manager.broadcast({"type": "alerts", "data": saved})

    await manager.broadcast({"type": "traffic", "count": len(parsed)})

    return parsed, saved


simulator = Simulator(on_batch=_process_lines, interval=3.0)


@app.get("/api/ping")
def ping():
    return {"status": "ok", "service": "logsentinel"}


@app.post("/api/analyze")
async def analyze(
    raw: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
):
    if file is not None:
        content = await file.read(MAX_ANALYZE_BYTES + 1)

        if len(content) > MAX_ANALYZE_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Input exceeds {MAX_ANALYZE_BYTES} byte limit.",
            )

        try:
            content_text = content.decode("utf-8")
        except UnicodeDecodeError:
            content_text = content.decode("utf-8", errors="replace")

    elif raw is not None:
        raw_bytes = raw.encode("utf-8")

        if len(raw_bytes) > MAX_ANALYZE_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Input exceeds {MAX_ANALYZE_BYTES} byte limit.",
            )

        content_text = raw

    else:
        raise HTTPException(
            status_code=400,
            detail="Provide 'raw' text or a file upload.",
        )

    lines = content_text.splitlines()

    if len(lines) > MAX_RAW_LINES:
        raise HTTPException(
            status_code=413,
            detail=f"Input exceeds {MAX_RAW_LINES} line limit.",
        )

    parsed, saved = await _process_lines(lines)

    return {
        "lines_received": len(lines),
        "parsed_entries": len(parsed),
        "alerts": saved,
    }


@app.get("/api/alerts")
def alerts(
    limit: int = 100,
    type: Optional[str] = None,
):
    if limit < 1 or limit > MAX_ALERT_LIMIT:
        raise HTTPException(
            status_code=400,
            detail=f"limit must be between 1 and {MAX_ALERT_LIMIT}.",
        )

    if type is not None and (len(type) > 100 or not type.strip()):
        raise HTTPException(status_code=400, detail="Invalid alert type.")

    return db.get_alerts(limit=limit, alert_type=type)


class AlertStatusUpdate(BaseModel):
    status: str
    resolution: Optional[str] = None


@app.get("/api/alerts/{event_id}")
def alert_detail(event_id: str):
    event = db.get_alert(event_id)

    if event is None:
        raise HTTPException(status_code=404, detail="Alert not found.")

    return event


@app.patch("/api/alerts/{event_id}/status")
def update_alert_status(event_id: str, update: AlertStatusUpdate):
    try:
        event = db.update_alert_status(
            event_id=event_id,
            status=update.status,
            resolution=update.resolution,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    if event is None:
        raise HTTPException(status_code=404, detail="Alert not found.")

    return event


@app.get("/api/stats")
def stats():
    return db.get_stats()


@app.post("/api/simulate/start")
async def simulate_start():
    simulator.start()
    return {"running": simulator.running}


@app.post("/api/simulate/stop")
async def simulate_stop():
    simulator.stop()
    return {"running": simulator.running}


@app.get("/api/simulate/status")
def simulate_status():
    return {"running": simulator.running}


@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket):
    connected = await manager.connect(websocket)

    if not connected:
        return

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def index():
    return FileResponse(str(STATIC_DIR / "index.html"))
