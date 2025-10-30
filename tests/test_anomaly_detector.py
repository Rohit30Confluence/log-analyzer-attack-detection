from analyzer.anomaly_detector import AnomalyDetector

def test_anomaly_detector_flags_high_volume_ips():
    logs = [
        "192.168.1.1 - - [28/Oct/2025] \"GET /index.html HTTP/1.1\" 200 -"
    ] * 100 + [
        "192.168.1.2 - - [28/Oct/2025] \"GET /index.html HTTP/1.1\" 200 -"
    ] * 10
    detector = AnomalyDetector(threshold=2.0)
    detector.fit(logs)
    anomalies = detector.detect()
    assert len(anomalies) == 1
    assert anomalies[0]["ip"] == "192.168.1.1"
