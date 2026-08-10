from app.detector import AttackDetector


def entry(ip, path, status, method="GET"):
    return {"ip": ip, "path": path, "status": status, "method": method}


def make_detector(threshold=3):
    return AttackDetector(bruteforce_threshold=threshold)


def test_brute_force_detected_over_threshold():
    d = make_detector(threshold=3)
    logs = [entry("10.0.0.2", "/login", 401) for _ in range(3)]
    alerts = d.detect(logs, run_anomaly=False)
    assert any(a["type"] == "Brute Force" for a in alerts)


def test_brute_force_not_detected_under_threshold():
    d = make_detector(threshold=5)
    logs = [entry("10.0.0.2", "/login", 401) for _ in range(2)]
    alerts = d.detect(logs, run_anomaly=False)
    assert not any(a["type"] == "Brute Force" for a in alerts)


def test_sql_injection_detected():
    d = make_detector()
    logs = [entry("127.0.0.1", "/search?q=' OR 1=1--", 200)]
    alerts = d.detect(logs, run_anomaly=False)
    assert any(a["type"] == "SQL Injection" for a in alerts)


def test_sql_injection_percent_encoded_detected():
    d = make_detector()
    logs = [entry("127.0.0.1", "/search?q=%27%20OR%201%3D1--", 200)]
    alerts = d.detect(logs, run_anomaly=False)
    assert any(a["type"] == "SQL Injection" for a in alerts)


def test_xss_detected():
    d = make_detector()
    logs = [entry("127.0.0.1", "/comment?msg=<script>alert(1)</script>", 200)]
    alerts = d.detect(logs, run_anomaly=False)
    assert any(a["type"] == "XSS" for a in alerts)


def test_path_traversal_detected():
    d = make_detector()
    logs = [entry("127.0.0.1", "/download?file=../../../../etc/passwd", 403)]
    alerts = d.detect(logs, run_anomaly=False)
    assert any(a["type"] == "Path Traversal" for a in alerts)


def test_clean_traffic_produces_no_alerts():
    d = make_detector()
    logs = [entry("1.2.3.4", "/index.html", 200)]
    alerts = d.detect(logs, run_anomaly=False)
    assert alerts == []


def test_referer_hash_does_not_false_positive_sqli():
    """A literal '#' in an unrelated path should not trip the SQLi comment pattern
    now that matching is scoped to the path only (regression test for the bug
    found in the previous version of this project)."""
    d = make_detector()
    logs = [entry("1.2.3.4", "/blog/post#section-2", 200)]
    alerts = d.detect(logs, run_anomaly=False)
    assert not any(a["type"] == "SQL Injection" for a in alerts)
