"""
Comprehensive End-to-End Test Suite.
Verifies visibility masking, feature extraction, traffic simulators,
and threat detection across all 5 mandatory threat categories.
"""

import pytest
import os
import numpy as np

from ingestion.schema import (
    PacketRecord,
    ThreatCategory,
    ThreatSeverity,
    VisibilityMask,
)
from features.visibility_mask import VisibilityMaskEngine
from features.dns_features import extract_dns_features, calculate_entropy
from traffic_simulator.scenario_manager import ScenarioManager
from traffic_simulator.scan_simulator import ScanTrafficGenerator
from traffic_simulator.flood_simulator import FloodTrafficGenerator
from traffic_simulator.dns_anomaly_simulator import DNSAnomalyTrafficGenerator
from traffic_simulator.beacon_simulator import BeaconTrafficGenerator
from traffic_simulator.slowloris_simulator import SlowlorisTrafficGenerator
from api.pipeline_manager import pipeline_manager


def test_entropy_calculation():
    """Verifies Shannon entropy on normal vs high-entropy strings."""
    normal_domain = "google.com"
    tunnel_domain = "4a7f89b12e34fa9c18d45efb019ac7"
    ent_norm = calculate_entropy(normal_domain)
    ent_tunnel = calculate_entropy(tunnel_domain)
    assert ent_tunnel > ent_norm
    assert ent_tunnel > 3.0


def test_dns_tunneling_feature_extraction():
    """Verifies DNS lexical and entropy feature extractor flags iodine/dnscat chunks."""
    suspicious_query = "4a7f89b12e34fa9c18d45efb019ac75e89d102ab3c4d5e.tunnel.darkcorp.net"
    feats = extract_dns_features(suspicious_query, "TXT")
    assert feats["is_suspicious_qtype"] is True
    assert feats["is_tunnel_signature"] is True
    assert feats["subdomain_length"] > 40


def test_visibility_mask_calibration():
    """Verifies Innovation 1: Visibility mask downweights reverse unobservables."""
    engine = VisibilityMaskEngine()
    mask = VisibilityMask(is_reverse_observable=False, data_quality_score=0.85)

    raw_features = {
        "packets_per_sec": 50.0,
        "bytes_per_sec": 25000.0,
        "ack_ratio": 0.9,  # normally suspicious if no reverse seen
        "syn_ratio": 0.8,
    }

    vec, mask_weights, vis_qual = engine.extract_masked_features(raw_features, mask)
    assert vis_qual > 0.0 and vis_qual <= 1.0

    calibrated_conf, note = engine.calibrate_confidence(0.95, vis_qual, "port_scan")
    assert calibrated_conf > 0.70
    assert "High confidence" in note


def test_scenario_manager_pcap_generation():
    """Verifies PCAP export with Scapy."""
    sm = ScenarioManager(pcap_dir="data/raw_pcaps")
    pkts = sm.generate_scenario("benign", benign_count=10)
    assert len(pkts) == 10

    pcap_path = sm.export_to_pcap(pkts, "test_benign.pcap")
    assert os.path.exists(pcap_path)
    assert os.path.getsize(pcap_path) > 0


def test_port_scan_detection():
    """Verifies port scan detection and evidence trail generation."""
    pipeline_manager.reset()
    scan_gen = ScanTrafficGenerator(attacker_ip="192.168.10.99", target_ip="10.0.0.50")
    pkts = scan_gen.generate_rapid_syn_scan(1700000000.0, port_count=25)

    alert = None
    for p in pkts:
        res = pipeline_manager.process_packet(p)
        if res:
            alert = res

    assert alert is not None
    assert alert.threat_type == ThreatCategory.PORT_SCAN
    assert alert.severity in [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]
    assert len(alert.evidence_trail) > 0
    assert any(e.feature_name == "unique_dst_ports" for e in alert.evidence_trail)


def test_syn_flood_detection():
    """Verifies SYN flood detection under high packet volume."""
    pipeline_manager.reset()
    flood_gen = FloodTrafficGenerator(attacker_ip="192.168.10.101", target_ip="10.0.0.80")
    pkts = flood_gen.generate_syn_flood(1700000100.0, count=60)

    alert = None
    for p in pkts:
        res = pipeline_manager.process_packet(p)
        if res:
            alert = res

    assert alert is not None
    assert alert.threat_type == ThreatCategory.SYN_FLOOD
    assert alert.severity == ThreatSeverity.CRITICAL


def test_dns_tunneling_detection():
    """Verifies detection of high-entropy DNS tunneling streams."""
    pipeline_manager.reset()
    dns_gen = DNSAnomalyTrafficGenerator(attacker_ip="192.168.10.102", dns_server="8.8.8.8")
    pkts = dns_gen.generate_dns_tunneling(1700000200.0, query_count=30)

    alert = None
    for p in pkts:
        res = pipeline_manager.process_packet(p)
        if res:
            alert = res

    assert alert is not None
    assert alert.threat_type == ThreatCategory.DNS_TUNNELING
    assert any("entropy" in e.feature_name for e in alert.evidence_trail)


def test_c2_beaconing_detection():
    """Verifies detection of periodic C2 beacon callbacks."""
    pipeline_manager.reset()
    beacon_gen = BeaconTrafficGenerator(
        infected_ip="192.168.10.103",
        c2_server="198.51.100.88",
        interval_sec=2.0,
        jitter_pct=0.10
    )
    pkts = beacon_gen.generate_beacons(1700000300.0, beacon_count=8)

    alert = None
    for p in pkts:
        res = pipeline_manager.process_packet(p)
        if res:
            alert = res

    assert alert is not None
    assert alert.threat_type == ThreatCategory.C2_BEACONING
    assert any(e.feature_name == "periodicity_score" for e in alert.evidence_trail)


def test_slowloris_detection():
    """Verifies slowloris HTTP header exhaustion detection with visibility notes."""
    pipeline_manager.reset()
    slow_gen = SlowlorisTrafficGenerator(attacker_ip="192.168.10.104", target_ip="10.0.0.80")
    pkts = slow_gen.generate_slowloris_attack(1700000400.0, connections=4, headers_per_conn=6)

    alert = None
    for p in pkts:
        res = pipeline_manager.process_packet(p)
        if res:
            alert = res

    assert alert is not None
    assert alert.threat_type == ThreatCategory.SLOWLORIS
    assert "incomplete" in alert.evidence_trail[1].interpretation.lower() or "http" in alert.evidence_trail[0].interpretation.lower()
