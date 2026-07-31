"""Tests for AnomalyDetector."""
from analyzer.anomaly_detector import AnomalyDetector


def _line(ip: str) -> str:
    return (
        f'{ip} - - [28/Oct/2025:10:00:00 +0000] '
        '"GET /index.html HTTP/1.1" 200 512'
    )


def test_flags_high_volume_ip():
    logs = [_line("192.168.1.1")] * 100 + [_line("192.168.1.2")] * 10
    d = AnomalyDetector(threshold=2.0)
    d.fit(logs)
    anomalies = d.detect()
    assert len(anomalies) == 1
    assert anomalies[0]["ip"] == "192.168.1.1"


def test_no_anomaly_on_uniform_traffic():
    logs = [_line(f"10.0.0.{i}") for i in range(1, 6)] * 10
    d = AnomalyDetector(threshold=2.0)
    d.fit(logs)
    assert d.detect() == []


def test_empty_input_no_crash():
    d = AnomalyDetector()
    d.fit([])
    assert d.detect() == []


def test_single_ip_no_anomaly():
    """Single IP: std=0, should return no anomalies."""
    logs = [_line("10.0.0.1")] * 20
    d = AnomalyDetector(threshold=2.0)
    d.fit(logs)
    assert d.detect() == []
