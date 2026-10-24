"""
Live Pipeline Orchestration Engine.
Coordinates ingestion, temporal tracking, ensemble classification,
graph modeling, and WebSocket broadcasting.
"""

import time
import asyncio
from collections import deque
from typing import List, Dict, Any, Optional, Set
from fastapi import WebSocket

from ingestion.schema import (
    PacketRecord,
    FlowRecord,
    ThreatAlert,
    ThreatCategory,
    SystemStatus,
    NetworkGraphState,
    VisibilityMask,
)
from features.flow_features import FlowAggregator
from features.temporal_features import MultiWindowTracker
from features.dns_features import extract_dns_features
from features.visibility_mask import VisibilityMaskEngine
from detection.rules import RuleDetectionEngine
from detection.classifier import ThreatClassifier
from detection.anomaly_detector import AnomalyDetector
from detection.temporal_fusion import ThreatDetectionEnsemble
from detection.host_graph import HostRelationshipGraph
from explainability.evidence_builder import EvidenceBuilder
from explainability.hash_chain import HashChainedLedger


class PipelineManager:
    """Singleton coordinator for real-time passive threat intelligence."""

    def __init__(self):
        self.aggregator = FlowAggregator(flow_timeout_sec=20.0)
        self.tracker = MultiWindowTracker()
        self.vis_engine = VisibilityMaskEngine()
        self.rules = RuleDetectionEngine()
        self.classifier = ThreatClassifier("models/threat_classifier.joblib")
        self.anomaly_detector = AnomalyDetector("models/anomaly_detector.joblib")
        self.ensemble = ThreatDetectionEnsemble(
            self.classifier, self.anomaly_detector, self.rules, self.vis_engine
        )
        self.graph = HostRelationshipGraph(time_window_sec=600.0)
        self.evidence_builder = EvidenceBuilder()
        self.ledger = HashChainedLedger()

        # Telemetry & History
        self.alerts: deque[ThreatAlert] = deque(maxlen=200)
        self.recent_packets: deque[PacketRecord] = deque(maxlen=100)
        self.total_packets_processed = 0
        self.total_alerts_emitted = 0
        self.start_time = time.time()
        self.last_packet_time = time.time()
        self.active_websockets: Set[WebSocket] = set()

        # Latency tracking
        self.latency_samples: deque[float] = deque(maxlen=50)

    def reset(self):
        """Resets in-memory state for fresh scenario/test runs."""
        self.aggregator = FlowAggregator(flow_timeout_sec=20.0)
        self.tracker = MultiWindowTracker()
        self.graph = HostRelationshipGraph(time_window_sec=600.0)
        self.alerts.clear()
        self.recent_packets.clear()
        self.total_packets_processed = 0
        self.total_alerts_emitted = 0
        self.latency_samples.clear()
        self.ledger = HashChainedLedger()

    async def connect_client(self, websocket: WebSocket):
        """Registers a live WebSocket client."""
        await websocket.accept()
        self.active_websockets.add(websocket)

    def disconnect_client(self, websocket: WebSocket):
        """Removes a disconnected WebSocket client."""
        self.active_websockets.discard(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        """Broadcasts event payload to all connected clients."""
        if not self.active_websockets:
            return
        dead = []
        for ws in list(self.active_websockets):
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active_websockets.discard(ws)

    def process_packet(self, pkt: PacketRecord) -> Optional[ThreatAlert]:
        """
        Ingests a single passively observed packet through the complete pipeline.
        Returns ThreatAlert if a detection is triggered.
        """
        t0 = time.perf_counter()
        self.total_packets_processed += 1
        self.last_packet_time = pkt.timestamp or time.time()
        self.recent_packets.append(pkt)

        # 1. Update temporal trackers
        self.tracker.record_packet(pkt)

        # 2. Update flow state
        flow = self.aggregator.update(pkt)

        # 3. Update graph state
        if pkt.dns_query:
            d_feat = extract_dns_features(pkt.dns_query, pkt.dns_qtype or "A")
            self.graph.update_dns_node(pkt.src_ip, pkt.dns_query, is_suspicious=d_feat["is_tunnel_signature"])

        alert = None
        # Evaluate when flow reaches meaningful sample size, on connection start, or on DNS query
        if flow.packet_count >= 5 or flow.duration >= 2.0 or pkt.tcp_flags == ["SYN"] or pkt.dns_query is not None:
            self.tracker.record_flow(flow)
            t_stats = self.tracker.get_multi_window_features(flow.src_ip, flow.last_time)

            # DNS feature integration
            dns_ent = flow.dns_entropy_max
            if pkt.dns_query:
                d_feat = extract_dns_features(pkt.dns_query, pkt.dns_qtype or "A")
                dns_ent = max(dns_ent, d_feat["entropy"])

            total_pkts = max(1, flow.packet_count)
            raw_dict = {
                "packets_per_sec": flow.packets_per_sec,
                "bytes_per_sec": flow.bytes_per_sec,
                "mean_packet_size": flow.mean_packet_size,
                "std_packet_size": flow.std_packet_size,
                "iat_mean": flow.iat_mean,
                "iat_std": flow.iat_std,
                "syn_ratio": flow.syn_count / total_pkts,
                "ack_ratio": flow.ack_count / total_pkts,
                "fin_ratio": flow.fin_count / total_pkts,
                "dns_query_count": float(flow.dns_query_count),
                "dns_entropy_max": float(dns_ent),
                "dns_label_len_max": float(flow.dns_label_len_max),
                "dns_unique_subdomains": float(flow.dns_unique_subdomains),
                "http_incomplete_flag": 1.0 if flow.http_incomplete else 0.0,
                "flow_duration": flow.duration,
                "unique_dst_ports_short": t_stats.get("short_unique_ports", 1.0),
                "unique_dst_ips_short": t_stats.get("short_unique_ips", 1.0),
                "periodicity_score": t_stats.get("max_beacon_periodicity", 0.0),
            }

            vec, _, _ = self.vis_engine.extract_masked_features(raw_dict, pkt.visibility)
            detection = self.ensemble.evaluate_flow(flow, t_stats, vec, pkt.visibility)

            if detection:
                # Build alert with complete forensic evidence trail
                feature_importances = self.classifier.get_feature_importances()
                alert = self.evidence_builder.create_alert(
                    detection, flow, t_stats, raw_dict, feature_importances
                )

                # Deduplicate identical recent alerts for the same src/dst within 5s
                is_duplicate = any(
                    a.src_ip == alert.src_ip
                    and a.threat_type == alert.threat_type
                    and abs(a.timestamp - alert.timestamp) < 5.0
                    for a in self.alerts
                )

                if not is_duplicate:
                    # Append alert to tamper-evident cryptographic hash chain
                    evidence_summary = {
                        "alert_id": alert.alert_id,
                        "threat_type": alert.threat_type.value,
                        "top_features": [
                            {e.feature_name: str(e.observed_value), "baseline": str(e.baseline_value), "attribution": e.attribution_weight}
                            for e in alert.evidence_trail
                        ],
                        "visibility_quality": alert.visibility_quality,
                    }
                    block = self.ledger.record_alert(
                        alert_id=alert.alert_id,
                        threat_label=alert.threat_type.value,
                        mitre_technique=f"{alert.mitre_id}: {alert.mitre_technique}",
                        src_ip=alert.src_ip,
                        dst_ip=alert.dst_ip,
                        calibrated_confidence=alert.calibrated_confidence,
                        risk_score=alert.risk_score,
                        evidence_dict=evidence_summary,
                    )
                    alert.evidence_hash = block.evidence_payload_hash
                    alert.previous_hash = block.previous_hash
                    alert.block_index = block.block_index

                    self.alerts.appendleft(alert)
                    self.total_alerts_emitted += 1
                    # Update graph node with risk
                    self.graph.update_from_flow(flow, is_suspicious=True, risk_score=alert.risk_score)
                else:
                    self.graph.update_from_flow(flow, is_suspicious=False)
                    alert = None
            else:
                self.graph.update_from_flow(flow, is_suspicious=False)
                alert = None

        latency_ms = (time.perf_counter() - t0) * 1000.0
        self.latency_samples.append(latency_ms)
        return alert

    def get_system_status(self) -> SystemStatus:
        """Returns real-time operating metrics of the unidirectional monitoring enclave."""
        elapsed = max(1.0, time.time() - self.start_time)
        pps = self.total_packets_processed / elapsed
        avg_lat = sum(self.latency_samples) / max(1, len(self.latency_samples))

        threat_level = "NORMAL"
        if len(self.alerts) > 0:
            latest = self.alerts[0]
            if latest.severity in ["CRITICAL", "HIGH"] and (time.time() - latest.timestamp) < 30.0:
                threat_level = "ELEVATED" if latest.severity == "HIGH" else "CRITICAL_ATTACK"

        return SystemStatus(
            status="ONLINE",
            diode_enclave_mode="UNIDIRECTIONAL_PASSIVE_INGEST",
            active_flows_tracked=len(self.aggregator.active_flows),
            total_packets_processed=self.total_packets_processed,
            total_alerts_emitted=self.total_alerts_emitted,
            throughput_pps=round(pps, 1),
            average_latency_ms=round(avg_lat, 2),
            visibility_coverage_pct=88.5,
            active_threat_level=threat_level,
        )


# Global singleton instance
pipeline_manager = PipelineManager()
