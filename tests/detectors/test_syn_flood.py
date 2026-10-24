import pytest
from detectors.syn_flood.detector import SynFloodDetector


def test_syn_flood_detection_on_attack():
    detector = SynFloodDetector()
    attack_window = {
        "dst_ip": "10.77.2.10",
        "ts_start": 1000.0,
        "ts_end": 1001.0,
        "syn_count": 450,
        "ack_count": 2,
        "syn_ratio": 0.995,
        "pps": 452.0,
        "source_entropy": 0.85,
    }
    alert = detector.predict(attack_window)
    assert alert is not None
    assert alert.threat == "syn_flood"
    assert alert.confidence >= 0.80
    assert "10.77.2.10" in alert.entities.dst_ips
    assert len(alert.evidence.rule_hits) >= 2


def test_syn_flood_ignores_benign():
    detector = SynFloodDetector()
    benign_window = {
        "dst_ip": "10.77.2.10",
        "ts_start": 1000.0,
        "ts_end": 1001.0,
        "syn_count": 5,
        "ack_count": 40,
        "syn_ratio": 0.11,
        "pps": 45.0,
        "source_entropy": 0.1,
    }
    alert = detector.predict(benign_window)
    assert alert is None
