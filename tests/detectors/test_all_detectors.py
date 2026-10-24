import pytest
from detectors.udp_flood.detector import UdpFloodDetector
from detectors.slowloris.detector import SlowlorisDetector
from detectors.dns_tunnel.detector import DnsTunnelDetector
from detectors.dga.detector import DgaDetector
from detectors.c2_beacon.detector import C2BeaconDetector
from detectors.anomaly.detector import AnomalyDetector


def test_udp_flood_detector():
    det = UdpFloodDetector()
    attack_feat = {
        "pps": 600.0,
        "byte_count": 300000,
        "proto": 17,
        "dst_ip": "10.77.2.53",
        "ts_start": 100.0,
        "ts_end": 101.0,
    }
    alert = det.predict(attack_feat)
    assert alert is not None
    assert alert.threat == "udp_flood"
    assert alert.confidence >= 0.70

    benign_feat = {"pps": 2.0, "byte_count": 500, "proto": 17, "dst_ip": "10.77.2.53"}
    assert det.predict(benign_feat) is None


def test_slowloris_detector():
    det = SlowlorisDetector()
    attack_feat = {
        "concurrent_flows": 65,
        "mean_flow_bytes": 350.0,
        "mean_flow_age": 45.0,
        "fin_rst_count": 0,
        "src_ip": "10.77.1.80",
        "dst_ip": "10.77.2.10",
        "ts_start": 100.0,
        "ts_end": 130.0,
    }
    alert = det.predict(attack_feat)
    assert alert is not None
    assert alert.threat == "slowloris"
    assert alert.confidence >= 0.75

    benign_feat = {"concurrent_flows": 2, "mean_flow_bytes": 15000.0, "fin_rst_count": 2}
    assert det.predict(benign_feat) is None


def test_dns_tunnel_detector():
    det = DnsTunnelDetector()
    attack_feat = {
        "qname": "a9f8b7c6d5e43210fe8b2c4d.tunnel.covert.org",
        "client_ip": "10.77.1.66",
        "resolver_ip": "10.77.2.53",
        "qtype": "TXT",
        "ts": 100.0,
    }
    alert = det.predict(attack_feat)
    assert alert is not None
    assert alert.threat == "dns_tunnel"
    assert alert.confidence >= 0.80

    benign_feat = {"qname": "portal.gov.in", "client_ip": "10.77.1.10", "qtype": "A", "ts": 100.0}
    assert det.predict(benign_feat) is None


def test_dga_detector():
    det = DgaDetector()
    attack_feat = {
        "qname": "vxzptwqjklnbmr49.cc",
        "client_ip": "10.77.1.180",
        "resolver_ip": "10.77.2.53",
        "ts": 100.0,
    }
    alert = det.predict(attack_feat)
    assert alert is not None
    assert alert.threat == "dga"

    benign_feat = {"qname": "nationalportal.gov.in", "client_ip": "10.77.1.10", "ts": 100.0}
    assert det.predict(benign_feat) is None


def test_c2_beacon_detector():
    det = C2BeaconDetector()
    attack_feat = {
        "event_count": 15,
        "iat_mean": 15.0,
        "iat_std": 0.45,
        "src_ip": "10.77.1.44",
        "dst_ip": "10.77.2.99",
        "dst_port": 8443,
        "ts_start": 100.0,
        "ts_end": 325.0,
    }
    alert = det.predict(attack_feat)
    assert alert is not None
    assert alert.threat == "c2_beacon"
    assert alert.confidence >= 0.75

    benign_feat = {"event_count": 15, "iat_mean": 15.0, "iat_std": 8.5}
    assert det.predict(benign_feat) is None


def test_anomaly_detector_confidence_cap():
    det = AnomalyDetector()
    outlier = {"anomaly_score": -0.65, "src_ip": "10.77.1.99", "dst_ip": "10.77.2.10", "dst_port": 9999}
    alert = det.predict(outlier)
    assert alert is not None
    assert alert.threat == "unclassified_anomaly"
    # Mandatory requirement: confidence must be capped <= 0.75
    assert alert.confidence <= 0.75
