"""
Data schemas and types for Unidirectional IP Traffic Threat Intelligence.
Tailored for passive hardware data diode / mirror tap monitoring enclaves.
"""

from enum import Enum
from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field
import time


class ThreatCategory(str, Enum):
    BENIGN = "benign"
    PORT_SCAN = "port_scan"
    SYN_FLOOD = "syn_flood"
    UDP_FLOOD = "udp_flood"
    SLOWLORIS = "slowloris"
    DNS_TUNNELING = "dns_tunneling"
    C2_BEACONING = "c2_beaconing"
    ANOMALY_UNKNOWN = "anomaly_unknown"


class ThreatSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class VisibilityMask(BaseModel):
    """
    Innovation 1: Visibility-Aware Observability Mask.
    Explicitly tracks what physical data diode tap is capable of observing.
    Prevents false assumptions that missing replies mean attacks or errors.
    """
    direction: str = "unidirectional_outbound"
    is_reverse_observable: bool = False
    can_observe_handshake_completion: bool = False
    can_observe_server_responses: bool = False
    can_observe_payload: bool = True
    data_quality_score: float = Field(default=0.85, ge=0.0, le=1.0)
    unobserved_fields: List[str] = Field(
        default_factory=lambda: [
            "tcp_ack_response",
            "server_http_status",
            "dns_response_nxdomain",
            "tcp_window_negotiation_reverse"
        ]
    )
    sensor_coverage_confidence: float = 0.95


class PacketRecord(BaseModel):
    """Normalized metadata for a single passively received packet."""
    timestamp: float = Field(default_factory=time.time)
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # TCP, UDP, ICMP, DNS, HTTP
    length: int
    tcp_flags: List[str] = Field(default_factory=list)  # SYN, ACK, FIN, RST, PSH, URG
    payload_preview: Optional[str] = None
    dns_query: Optional[str] = None
    dns_qtype: Optional[str] = None
    http_method: Optional[str] = None
    http_uri: Optional[str] = None
    http_headers: Optional[Dict[str, str]] = None
    visibility: VisibilityMask = Field(default_factory=VisibilityMask)


class FlowRecord(BaseModel):
    """
    Unidirectional Flow (UniFlow) record aggregated over a temporal observation window.
    Designed to work without requiring bidirectionality.
    """
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    last_time: float
    duration: float
    packet_count: int = 0
    byte_count: int = 0
    packets_per_sec: float = 0.0
    bytes_per_sec: float = 0.0
    mean_packet_size: float = 0.0
    std_packet_size: float = 0.0
    iat_mean: float = 0.0
    iat_std: float = 0.0
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    dns_query_count: int = 0
    dns_entropy_max: float = 0.0
    dns_label_len_max: int = 0
    dns_unique_subdomains: int = 0
    http_incomplete: bool = False
    http_header_count: int = 0
    visibility: VisibilityMask = Field(default_factory=VisibilityMask)


class EvidenceItem(BaseModel):
    """
    Structured forensic evidence item explaining a detection decision.
    """
    feature_name: str
    observed_value: Any
    baseline_value: Any
    attribution_weight: float  # SHAP-like normalized contribution (-1.0 to 1.0)
    interpretation: str


class ThreatAlert(BaseModel):
    """
    Analyst-Readable Threat Alert containing full explainability trail
    and visibility calibrations for hardware data diode enclaves.
    """
    alert_id: str
    timestamp: float = Field(default_factory=time.time)
    threat_type: ThreatCategory
    severity: ThreatSeverity
    risk_score: float = Field(ge=0.0, le=100.0)  # 0 to 100
    model_confidence: float = Field(ge=0.0, le=1.0)
    calibrated_confidence: float = Field(ge=0.0, le=1.0)
    visibility_quality: float = Field(ge=0.0, le=1.0)
    src_ip: str
    dst_ip: Optional[str] = None
    target_ports: List[int] = Field(default_factory=list)
    flow_count: int = 1
    evidence_trail: List[EvidenceItem] = Field(default_factory=list)
    visibility_notes: str
    recommended_action: str
    detection_layer: str = "Multi-Window Ensemble"  # Rule, Classifier, Anomaly, Fusion


class HostProfile(BaseModel):
    """Baseline profile of a network endpoint for drift-aware and temporal analysis."""
    ip: str
    first_seen: float
    last_seen: float
    total_flows: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    known_ports: List[int] = Field(default_factory=list)
    known_destinations: List[str] = Field(default_factory=list)
    avg_pps: float = 0.0
    dns_query_baseline_entropy: float = 2.5
    beacon_periodicity_score: float = 0.0
    risk_rating: float = 0.0


class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # host, external_ip, domain, port
    risk_score: float = 0.0
    alert_count: int = 0


class GraphEdge(BaseModel):
    source: str
    target: str
    protocol: str
    flow_count: int = 1
    byte_count: int = 0
    last_seen: float
    is_suspicious: bool = False


class NetworkGraphState(BaseModel):
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    timestamp: float = Field(default_factory=time.time)


class SystemStatus(BaseModel):
    status: str = "ONLINE"
    diode_enclave_mode: str = "UNIDIRECTIONAL_PASSIVE_INGEST"
    active_flows_tracked: int = 0
    total_packets_processed: int = 0
    total_alerts_emitted: int = 0
    throughput_pps: float = 0.0
    average_latency_ms: float = 0.0
    visibility_coverage_pct: float = 85.0
    active_threat_level: str = "NORMAL"
