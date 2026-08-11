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

def test_xss_payload_is_returned_as_data_not_executable_markup():
    malicious = (
        '198.51.100.50 - - [10/Aug/2026:09:01:00 +0000] '
        '"GET /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1" '
        '200 220 "-" "-"'
    )

    res = client.post("/api/analyze", data={"raw": malicious})

    assert res.status_code == 200

    body = res.json()
    assert body["parsed_entries"] == 1
    assert any(a["type"] == "XSS" for a in body["alerts"])


def test_security_headers_are_present():
    res = client.get("/api/ping")
    assert res.status_code == 200
    assert res.headers["x-content-type-options"] == "nosniff"
    assert res.headers["x-frame-options"] == "DENY"
    assert res.headers["referrer-policy"] == "no-referrer"


def test_alert_limit_is_bounded():
    res = client.get("/api/alerts?limit=201")
    assert res.status_code == 400


def test_alert_limit_rejects_zero():
    res = client.get("/api/alerts?limit=0")
    assert res.status_code == 400


def test_analyze_rejects_oversized_raw_input():
    oversized = "x" * (2 * 1024 * 1024 + 1)

    res = client.post("/api/analyze", data={"raw": oversized})

    assert res.status_code == 413


def test_cors_does_not_allow_arbitrary_origin():
    res = client.get(
        "/api/ping",
        headers={"Origin": "https://evil.example"},
    )

    assert res.status_code == 200
    assert "access-control-allow-origin" not in res.headers


def test_security_event_contract_is_persisted():
    res = client.post("/api/analyze", data={"raw": SAMPLE_LOG})

    assert res.status_code == 200

    body = res.json()
    assert body["alerts"]

    event = body["alerts"][0]

    assert event["event_id"]
    assert event["event_version"] == "1.0"
    assert event["event_type"]
    assert event["detector"]
    assert event["rule_id"]
    assert 0.0 <= event["confidence"] <= 1.0
    assert "observed_at" in event
    assert "metadata" in event

    # Compatibility fields remain available to the existing dashboard.
    assert event["type"] == event["event_type"]
    assert event["ip"] == event["source_ip"]


def test_alert_filter_uses_canonical_event_type():
    client.post("/api/analyze", data={"raw": SAMPLE_LOG})

    res = client.get("/api/alerts?type=SQL%20Injection")

    assert res.status_code == 200
    assert res.json()
    assert all(
        event["event_type"] == "SQL Injection"
        for event in res.json()
    )


def test_stats_use_canonical_event_type():
    client.post("/api/analyze", data={"raw": SAMPLE_LOG})

    res = client.get("/api/stats")

    assert res.status_code == 200
    body = res.json()

    assert "SQL Injection" in body["by_type"]
    assert "Brute Force" in body["by_type"]


def _lifecycle_log(ip: str, path: str = "/login") -> str:
    lines = [
        f'{ip} - - [12/Aug/2026:01:00:0{i} +0000] '
        f'"POST {path} HTTP/1.1" 401 0 "-" "-"'
        for i in range(5)
    ]
    return "\n".join(lines)


LIFECYCLE_LOG_OPEN = _lifecycle_log("198.18.0.10", "/lifecycle-open")
LIFECYCLE_LOG_REPEAT = _lifecycle_log("198.18.0.11", "/lifecycle-repeat")
LIFECYCLE_LOG_STATUS = _lifecycle_log("198.18.0.12", "/lifecycle-status")


def test_security_event_starts_open():
    res = client.post("/api/analyze", data={"raw": LIFECYCLE_LOG_OPEN})

    assert res.status_code == 200

    event = res.json()["alerts"][0]

    assert event["status"] == "open"
    assert event["occurrence_count"] == 1
    assert event["correlation_id"]


def test_repeated_event_is_correlated():
    first = client.post("/api/analyze", data={"raw": LIFECYCLE_LOG_REPEAT})
    second = client.post("/api/analyze", data={"raw": LIFECYCLE_LOG_REPEAT})

    assert first.status_code == 200
    assert second.status_code == 200

    first_events = first.json()["alerts"]
    second_events = second.json()["alerts"]

    assert first_events
    assert second_events

    first_event = first_events[0]
    second_event = second_events[0]

    assert second_event["event_id"] == first_event["event_id"]
    assert second_event["correlation_id"] == first_event["correlation_id"]
    assert second_event["occurrence_count"] == 2


def test_alert_status_can_be_acknowledged():
    res = client.post("/api/analyze", data={"raw": LIFECYCLE_LOG_STATUS})

    event_id = res.json()["alerts"][0]["event_id"]

    res = client.patch(
        f"/api/alerts/{event_id}/status",
        json={"status": "acknowledged"},
    )

    assert res.status_code == 200
    assert res.json()["status"] == "acknowledged"


def test_alert_status_follows_lifecycle():
    res = client.post("/api/analyze", data={"raw": LIFECYCLE_LOG_STATUS})

    event_id = res.json()["alerts"][0]["event_id"]

    for status in ("acknowledged", "investigating", "contained", "resolved"):
        res = client.patch(
            f"/api/alerts/{event_id}/status",
            json={"status": status},
        )

        assert res.status_code == 200
        assert res.json()["status"] == status


def test_invalid_lifecycle_transition_is_rejected():
    res = client.post("/api/analyze", data={"raw": LIFECYCLE_LOG_STATUS})

    event_id = res.json()["alerts"][0]["event_id"]

    res = client.patch(
        f"/api/alerts/{event_id}/status",
        json={"status": "resolved"},
    )

    assert res.status_code == 200

    res = client.patch(
        f"/api/alerts/{event_id}/status",
        json={"status": "investigating"},
    )

    assert res.status_code == 400


def test_unknown_alert_returns_404():
    res = client.get(
        "/api/alerts/00000000-0000-0000-0000-000000000000"
    )

    assert res.status_code == 404

def test_analyze_attaches_response_decision():
    log = "\n".join(
        f'198.18.0.77 - - [12/Aug/2026:01:00:0{i} +0000] '
        f'"POST /response-test HTTP/1.1" 401 0 "-" "-"'
        for i in range(5)
    )

    res = client.post("/api/analyze", data={"raw": log})

    assert res.status_code == 200

    body = res.json()
    assert body["alerts"]

    response = body["alerts"][0]["response"]

    assert response["action"] == "observe"
    assert response["policy_id"] == "response.default.v1"
    assert response["reason"]
    assert response["requires_approval"] is False
