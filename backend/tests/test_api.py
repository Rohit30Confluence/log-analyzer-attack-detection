import os
import tempfile

# Point at an isolated throwaway DB before importing the app, so tests never
# touch a developer's real logsentinel.db.
_tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
os.environ["LOGSENTINEL_DB"] = _tmp_db.name

from fastapi.testclient import TestClient  # noqa: E402
from app.main import app  # noqa: E402

# Using TestClient as a context manager triggers FastAPI's startup event
# (which creates the SQLite tables) exactly the way a real ASGI server would.
client = TestClient(app)
with client:
    pass

SAMPLE_LOG = (
    '203.0.113.9 - - [10/Aug/2026:09:00:05 +0000] "POST /login HTTP/1.1" 401 0 "-" "-"\n'
    '203.0.113.9 - - [10/Aug/2026:09:00:06 +0000] "POST /login HTTP/1.1" 401 0 "-" "-"\n'
    '203.0.113.9 - - [10/Aug/2026:09:00:07 +0000] "POST /login HTTP/1.1" 401 0 "-" "-"\n'
    '203.0.113.9 - - [10/Aug/2026:09:00:08 +0000] "POST /login HTTP/1.1" 401 0 "-" "-"\n'
    '203.0.113.9 - - [10/Aug/2026:09:00:09 +0000] "POST /login HTTP/1.1" 401 0 "-" "-"\n'
    '203.0.113.12 - - [10/Aug/2026:09:00:12 +0000] "GET /search?q=%27%20OR%201%3D1-- HTTP/1.1" 200 220 "-" "-"\n'
)


def test_ping():
    res = client.get("/api/ping")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


def test_analyze_returns_alerts():
    res = client.post("/api/analyze", data={"raw": SAMPLE_LOG})
    assert res.status_code == 200
    body = res.json()
    assert body["parsed_entries"] == 6
    types = {a["type"] for a in body["alerts"]}
    assert "Brute Force" in types
    assert "SQL Injection" in types


def test_alerts_endpoint_reflects_analysis():
    client.post("/api/analyze", data={"raw": SAMPLE_LOG})
    res = client.get("/api/alerts")
    assert res.status_code == 200
    assert len(res.json()) > 0


def test_stats_endpoint():
    client.post("/api/analyze", data={"raw": SAMPLE_LOG})
    res = client.get("/api/stats")
    assert res.status_code == 200
    body = res.json()
    assert body["total_alerts"] > 0
    assert "by_type" in body


def test_dashboard_served_at_root():
    res = client.get("/")
    assert res.status_code == 200
    assert "LogSentinel" in res.text


def test_simulate_start_stop():
    res = client.post("/api/simulate/start")
    assert res.json()["running"] is True
    res = client.post("/api/simulate/stop")
    assert res.json()["running"] is False
