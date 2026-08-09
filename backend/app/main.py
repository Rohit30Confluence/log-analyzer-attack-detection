"""
LogSentinel API — fully local, zero external services.

Endpoints:
  GET  /api/ping                — liveness
  POST /api/analyze             — one-shot analysis of uploaded/pasted log text
  GET  /api/alerts              — recent alerts (from SQLite)
  GET  /api/stats               — summary counts
  POST /api/simulate/start      — start the live traffic simulator
  POST /api/simulate/stop       — stop it
  GET  /api/simulate/status     — is it running
  WS   /ws/live                 — live alert stream (used by the dashboard)
  GET  /                        — static dashboard (no build step, vanilla JS)
"""
from __future__ import annotations

import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, File, Form, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from . import db
from .detector import AttackDetector
from .parser import parse_text
from .simulator import Simulator

APP_ROOT = Path(__file__).resolve().parents[1]
STATIC_DIR = APP_ROOT / "static"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init_db()
    yield


app = FastAPI(title="LogSentinel", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

detector = AttackDetector()


# ---------------------------------------------------------------------------
# WebSocket connection manager
# ---------------------------------------------------------------------------
class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

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
    """Shared pipeline: parse -> detect -> persist -> broadcast. Used by both
    /api/analyze and the simulator, so there is exactly one code path."""
    text = "\n".join(lines)
    parsed = list(parse_text(text))
    alerts = detector.detect(parsed)
    saved = db.save_alerts(alerts) if alerts else []
    if saved:
        await manager.broadcast({"type": "alerts", "data": saved})
    await manager.broadcast({"type": "traffic", "count": len(parsed)})
    return parsed, saved


simulator = Simulator(on_batch=_process_lines, interval=3.0)


# ---------------------------------------------------------------------------
# REST routes
# ---------------------------------------------------------------------------
@app.get("/api/ping")
def ping():
    return {"status": "ok", "service": "logsentinel"}


@app.post("/api/analyze")
async def analyze(raw: Optional[str] = Form(None), file: Optional[UploadFile] = File(None)):
    if file is not None:
        content = (await file.read()).decode(errors="ignore")
    elif raw:
        content = raw
    else:
        return {"error": "Provide 'raw' text or a file upload."}

    lines = content.splitlines()
    parsed, saved = await _process_lines(lines)
    return {
        "lines_received": len(lines),
        "parsed_entries": len(parsed),
        "alerts": saved,
    }


@app.get("/api/alerts")
def alerts(limit: int = 100, type: Optional[str] = None):
    return db.get_alerts(limit=limit, alert_type=type)


@app.get("/api/stats")
def stats():
    return db.get_stats()


@app.post("/api/simulate/start")
async def simulate_start():
    # Must be an async endpoint: it runs on the event loop thread, which is
    # required for asyncio.create_task() inside simulator.start(). A sync
    # endpoint runs in a worker thread with no running loop and would fail.
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
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # keep-alive / ignore client pings
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ---------------------------------------------------------------------------
# Static dashboard (no build step — plain HTML/CSS/JS)
# ---------------------------------------------------------------------------
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def index():
    return FileResponse(str(STATIC_DIR / "index.html"))
