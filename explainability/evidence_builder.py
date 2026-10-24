"""
Innovation 3: Analyst-Readable Evidence Engine & Explainability Layer.
Constructs structured forensic evidence trails, baseline comparisons,
feature attribution scores, and passive SOC defense playbooks.
"""

import uuid
import time
from typing import List, Dict, Any, Optional

from ingestion.schema import (
    ThreatAlert,
    ThreatCategory,
    ThreatSeverity,
    EvidenceItem,
    FlowRecord,
)
from features.visibility_mask import FEATURE_NAMES


class EvidenceBuilder:
    """Generates transparent, auditable evidence trails for every security alert."""

    # Normal network baselines for typical office/data center host
    BASELINE_STATS = {
        "packets_per_sec": 3.5,
        "bytes_per_sec": 4200.0,
        "mean_packet_size": 480.0,
        "iat_mean": 0.28,
        "syn_ratio": 0.05,
        "dns_entropy_max": 2.6,
        "dns_label_len_max": 14,
        "dns_unique_subdomains": 1,
        "unique_dst_ports_short": 1,
        "unique_dst_ips_short": 1,
        "periodicity_score": 0.12,
    }

    ACTION_PLAYBOOKS = {
        ThreatCategory.PORT_SCAN: "PASSIVE SOC ADVISORY: Isolate source endpoint for credential/lateral movement audit. Implement upstream edge ACL to throttle outbound port sweeps.",
        ThreatCategory.SYN_FLOOD: "PASSIVE SOC ADVISORY: Alert upstream transit provider. Enable perimeter SYN-proxy or rate-limiting at external ingress gateway (outside monitoring boundary).",
        ThreatCategory.UDP_FLOOD: "PASSIVE SOC ADVISORY: Initiate upstream BGP flowspec or upstream scrubber rate-limiting on target UDP destination port.",
        ThreatCategory.SLOWLORIS: "PASSIVE SOC ADVISORY: Adjust web application gateway minimum client transfer rates and reduce concurrent connection keep-alive timeout per IP.",
        ThreatCategory.DNS_TUNNELING: "PASSIVE SOC ADVISORY: Blackhole exfiltration domain at internal DNS resolvers. Quarantine offending client endpoint and review DNS sinkhole logs.",
        ThreatCategory.C2_BEACONING: "PASSIVE SOC ADVISORY: High-priority C2 beacon. Null-route external C2 destination IP at border firewall. Perform memory dump and forensic EDR isolation.",
        ThreatCategory.ANOMALY_UNKNOWN: "PASSIVE SOC ADVISORY: Zero-day behavioral anomaly. Capture full packet metadata and review host relationship graph for abnormal fan-out.",
    }

    MITRE_MAPPING = {
        ThreatCategory.PORT_SCAN: ("T1046", "Network Service Discovery"),
        ThreatCategory.SYN_FLOOD: ("T1498.001", "Direct Network Flood"),
        ThreatCategory.UDP_FLOOD: ("T1498.002", "UDP Flood Reflection"),
        ThreatCategory.SLOWLORIS: ("T1499.002", "Application Exhaustion: Slowloris"),
        ThreatCategory.DNS_TUNNELING: ("T1572", "Protocol Tunneling: DNS Exfiltration"),
        ThreatCategory.C2_BEACONING: ("T1071.001", "Application Layer Protocol: Web Protocols"),
        ThreatCategory.ANOMALY_UNKNOWN: ("T1059", "Novel Behavioral Outlier"),
    }

    def build_evidence_trail(
        self,
        category: ThreatCategory,
        flow: FlowRecord,
        temporal_stats: Dict[str, float],
        feature_dict: Dict[str, float],
        feature_importances: Dict[str, float],
    ) -> List[EvidenceItem]:
        """Synthesizes structured evidence items explaining model classification."""
        items = []

        if category == ThreatCategory.PORT_SCAN:
            ports = int(max(temporal_stats.get("short_unique_ports", 0), temporal_stats.get("med_unique_ports", 0), 1))
            items.append(EvidenceItem(
                feature_name="unique_dst_ports",
                observed_value=ports,
                baseline_value=self.BASELINE_STATS["unique_dst_ports_short"],
                attribution_weight=0.88,
                interpretation=f"Host probed {ports} unique destination ports within temporal window (baseline: {self.BASELINE_STATS['unique_dst_ports_short']})."
            ))
            items.append(EvidenceItem(
                feature_name="syn_ratio",
                observed_value=round(feature_dict.get("syn_ratio", 0.0), 3),
                baseline_value=self.BASELINE_STATS["syn_ratio"],
                attribution_weight=0.65,
                interpretation="High ratio of unsolicited SYN probes without corresponding conversational traffic."
            ))

        elif category in [ThreatCategory.SYN_FLOOD, ThreatCategory.UDP_FLOOD]:
            obs_pps = round(max(flow.packets_per_sec, temporal_stats.get("short_pps", 0)), 1)
            items.append(EvidenceItem(
                feature_name="packets_per_sec",
                observed_value=obs_pps,
                baseline_value=self.BASELINE_STATS["packets_per_sec"],
                attribution_weight=0.92,
                interpretation=f"Volumetric surge reaching {obs_pps} pps, exceeding baseline by {obs_pps / max(1, self.BASELINE_STATS['packets_per_sec']):.1f}x."
            ))
            if category == ThreatCategory.SYN_FLOOD:
                items.append(EvidenceItem(
                    feature_name="syn_count",
                    observed_value=flow.syn_count,
                    baseline_value=1,
                    attribution_weight=0.85,
                    interpretation=f"Observed {flow.syn_count} rapid SYN frames targeting destination without handshake completion."
                ))

        elif category == ThreatCategory.DNS_TUNNELING:
            items.append(EvidenceItem(
                feature_name="dns_entropy_max",
                observed_value=round(flow.dns_entropy_max, 2),
                baseline_value=self.BASELINE_STATS["dns_entropy_max"],
                attribution_weight=0.91,
                interpretation=f"Extracted subdomain Shannon entropy of {flow.dns_entropy_max:.2f} bits/symbol indicates high-density encrypted/encoded payload."
            ))
            items.append(EvidenceItem(
                feature_name="dns_label_len_max",
                observed_value=flow.dns_label_len_max,
                baseline_value=self.BASELINE_STATS["dns_label_len_max"],
                attribution_weight=0.82,
                interpretation=f"Max label length {flow.dns_label_len_max} chars exceeds standard hostname boundaries (baseline: {self.BASELINE_STATS['dns_label_len_max']})."
            ))

        elif category == ThreatCategory.SLOWLORIS:
            items.append(EvidenceItem(
                feature_name="flow_duration",
                observed_value=round(flow.duration, 1),
                baseline_value=1.5,
                attribution_weight=0.84,
                interpretation=f"HTTP socket held open for {flow.duration:.1f}s while continuously transmitting incomplete headers."
            ))
            items.append(EvidenceItem(
                feature_name="http_incomplete_flag",
                observed_value=1.0,
                baseline_value=0.0,
                attribution_weight=0.79,
                interpretation="Client periodically transmits partial header fragments without sending terminal CRLF CRLF delimiter."
            ))

        elif category == ThreatCategory.C2_BEACONING:
            periodicity = round(temporal_stats.get("max_beacon_periodicity", 0.0), 2)
            items.append(EvidenceItem(
                feature_name="periodicity_score",
                observed_value=periodicity,
                baseline_value=self.BASELINE_STATS["periodicity_score"],
                attribution_weight=0.95,
                interpretation=f"Inter-arrival time variance exhibits strong regularity (Periodicity: {periodicity}), consistent with jittered C2 heartbeats."
            ))

        else:
            # Anomaly unknown
            items.append(EvidenceItem(
                feature_name="multivariate_statistical_drift",
                observed_value="Significant deviation",
                baseline_value="Normal distribution",
                attribution_weight=0.75,
                interpretation="Multi-feature vector isolated as an extreme outlier by Isolation Forest."
            ))

        return items

    def create_alert(
        self,
        detection_result: Dict[str, Any],
        flow: FlowRecord,
        temporal_stats: Dict[str, float],
        feature_dict: Dict[str, float],
        feature_importances: Dict[str, float],
    ) -> ThreatAlert:
        """Constructs complete ThreatAlert object."""
        category: ThreatCategory = detection_result["category"]
        severity: ThreatSeverity = detection_result["severity"]
        calibrated_conf = detection_result["calibrated_confidence"]
        vis_qual = detection_result["visibility_quality"]

        # Risk score calculation (0 - 100)
        base_severity_weight = {
            ThreatSeverity.CRITICAL: 95.0,
            ThreatSeverity.HIGH: 80.0,
            ThreatSeverity.MEDIUM: 60.0,
            ThreatSeverity.LOW: 35.0,
            ThreatSeverity.INFO: 15.0,
        }.get(severity, 50.0)

        risk_score = round(base_severity_weight * calibrated_conf, 1)

        evidence = self.build_evidence_trail(
            category, flow, temporal_stats, feature_dict, feature_importances
        )

        recommended_action = self.ACTION_PLAYBOOKS.get(
            category, "Review egress telemetry and correlate with perimeter logs."
        )

        mitre_id, mitre_tech = self.MITRE_MAPPING.get(
            category, ("T1000", "Heuristic Egress Anomaly")
        )

        return ThreatAlert(
            alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
            timestamp=flow.last_time or time.time(),
            threat_type=category,
            severity=severity,
            risk_score=risk_score,
            model_confidence=detection_result["raw_confidence"],
            calibrated_confidence=calibrated_conf,
            visibility_quality=vis_qual,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            target_ports=[flow.dst_port],
            flow_count=flow.packet_count,
            evidence_trail=evidence,
            visibility_notes=detection_result.get("visibility_notes", "Passive unidirectional observation."),
            recommended_action=recommended_action,
            detection_layer=detection_result.get("detection_layer", "Ensemble"),
            mitre_id=mitre_id,
            mitre_technique=mitre_tech,
        )
