"""
Passive-Proof CI Verification Test.
Demonstrates and strictly verifies that CyberThread/DiodeWatch operates in 100% passive mode:
- ZERO egress network connections are attempted
- ZERO reverse DNS queries (socket.gethostbyaddr) are made
- ZERO packets or probes flow back towards the monitored network
- The entire ingestion, detection, and forensic evidence generation completes in strict isolation.
"""

import socket
import pytest
from unittest.mock import patch, MagicMock

from api.pipeline_manager import pipeline_manager
from traffic_simulator.scenario_manager import ScenarioManager
from ingestion.schema import ThreatCategory


class EgressViolationException(Exception):
    """Raised whenever code attempts to send network traffic back across the boundary."""
    pass


def test_passive_proof_zero_egress_guarantee():
    """
    Rigorously tests that processing malicious traffic scenarios
    never initiates any outbound network calls or probes across the data diode.
    """
    pipeline_manager.reset()
    scenario_mgr = ScenarioManager()

    # Track any outgoing network attempts
    attempted_outbound_calls = []

    def mock_socket_connect(self, address):
        attempted_outbound_calls.append(("socket.connect", address))
        raise EgressViolationException(f"Hardware Diode Violation: Attempted outbound connect to {address}")

    def mock_socket_send(self, data, *args):
        attempted_outbound_calls.append(("socket.send", len(data)))
        raise EgressViolationException(f"Hardware Diode Violation: Attempted outbound send ({len(data)} bytes)")

    def mock_gethostbyaddr(ip):
        attempted_outbound_calls.append(("socket.gethostbyaddr", ip))
        raise EgressViolationException(f"Hardware Diode Violation: Attempted reverse DNS query for {ip}")

    # Patch Python network primitives to catch any rogue egress
    with patch.object(socket.socket, 'connect', mock_socket_connect), \
         patch.object(socket.socket, 'send', mock_socket_send), \
         patch.object(socket.socket, 'sendto', mock_socket_send), \
         patch.object(socket, 'gethostbyaddr', mock_gethostbyaddr):

        # Generate multi-vector attack traffic (Port scan, SYN flood, DNS tunneling, Beacon)
        packets = scenario_mgr.generate_scenario("all", benign_count=20, attack_intensity=30)
        assert len(packets) > 50

        # Feed all packets into the unidirectional enclave pipeline
        alerts_raised = []
        for pkt in packets:
            alert = pipeline_manager.process_packet(pkt)
            if alert:
                alerts_raised.append(alert)

        # STRICT ASSERTIONS:
        # 1. Zero outbound calls or probes were attempted across the monitored link
        assert len(attempted_outbound_calls) == 0, f"Diode breach detected! Outbound calls: {attempted_outbound_calls}"

        # 2. Threats were successfully detected passively inside the enclave
        assert len(alerts_raised) > 0
        detected_categories = {a.threat_type for a in alerts_raised}
        assert len(detected_categories) >= 2

        # 3. Every alert contains tamper-evident cryptographic hash-chain linkage
        for alert in alerts_raised:
            assert alert.evidence_hash is not None
            assert len(alert.evidence_hash) == 64  # valid SHA-256 hex string
            assert alert.previous_hash is not None
            assert alert.block_index is not None and alert.block_index >= 1

        # 4. Verify integrity of the entire cryptographic ledger
        verification = pipeline_manager.ledger.verify_chain_integrity()
        assert verification["valid"] is True
        assert verification["status"] == "CRYPTOGRAPHICALLY_VERIFIED_APPEND_ONLY"


def test_hash_chain_tamper_detection():
    """
    Verifies that the tamper-evident hash chain detects any unauthorized
    tampering, deletion, or modification of stored forensic evidence.
    """
    pipeline_manager.reset()
    ledger = pipeline_manager.ledger

    # Record 3 sample alerts
    block1 = ledger.record_alert("ALT-001", "port_scan", "T1046", "192.168.1.10", "10.0.0.1", 0.95, 80.0, {"ports": 20})
    block2 = ledger.record_alert("ALT-002", "syn_flood", "T1498.001", "192.168.1.20", "10.0.0.1", 0.98, 90.0, {"pps": 500})
    block3 = ledger.record_alert("ALT-003", "dns_tunneling", "T1572", "192.168.1.30", "8.8.8.8", 0.92, 85.0, {"entropy": 4.2})

    # Integrity should be 100% valid initially
    assert ledger.verify_chain_integrity()["valid"] is True

    # Simulate adversary tampering with block 2's evidence hash
    original_hash = block2.evidence_payload_hash
    block2.evidence_payload_hash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

    # Integrity verification must catch the tamper
    tamper_result = ledger.verify_chain_integrity()
    assert tamper_result["valid"] is False
    assert tamper_result["tampered_block_index"] == 2

    # Restore and verify it passes again
    block2.evidence_payload_hash = original_hash
    assert ledger.verify_chain_integrity()["valid"] is True
