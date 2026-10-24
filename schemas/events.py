"""
Canonical event schemas for SIH 2026 PS 26145.
All stages (ingest, normalizer, feature engine, detectors, fusion, blockchain)
use these stable, versioned schemas.
"""

from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field
import time
import uuid


class FlowEvent(BaseModel):
    """
    Canonical FlowEvent representing a forward-only unidirectional flow record.
    Never relies on server responses or reverse SYN-ACKs.
    """
    ts_start: float
    ts_end: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int  # 6 = TCP, 17 = UDP, 1 = ICMP
    packets: int
    bytes: int
    tcp_flags_union: int = 0
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    min_ttl: int = 64
    max_ttl: int = 64
    mean_pkt_len: float = 0.0
    std_pkt_len: float = 0.0
    iat_mean: float = 0.0
    iat_std: float = 0.0
    direction_seen: Literal["fwd", "both"] = "fwd"
    source: Literal["pcap", "netflow", "ipfix", "sflow"] = "pcap"


class DnsEvent(BaseModel):
    """
    Canonical DnsEvent representing a passively extracted DNS query.
    Extracted from the forward direction only (no NXDOMAIN or server responses).
    """
    ts: float
    client_ip: str
    resolver_ip: str
    qname: str
    qtype: str = "A"
    qclass: str = "IN"
    edns_present: bool = False
    payload_len: int = 0


class AlertEntities(BaseModel):
    src_ips: List[str] = Field(default_factory=list)
    dst_ips: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    ports: List[int] = Field(default_factory=list)


class AlertEvidence(BaseModel):
    top_features: Dict[str, float] = Field(default_factory=dict)
    metric_timeseries: Dict[str, List[float]] = Field(default_factory=dict)
    sample_flows: List[Dict[str, Any]] = Field(default_factory=list)
    rule_hits: List[str] = Field(default_factory=list)


class Alert(BaseModel):
    """
    Canonical Alert schema conforming to CLAUDE.md.
    """
    alert_id: str = Field(default_factory=lambda: f"alt-{uuid.uuid4().hex[:8]}")
    ts_start: float
    ts_end: float
    threat: str
    confidence: float  # Calibrated probability [0.0, 1.0]
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    entities: AlertEntities = Field(default_factory=AlertEntities)
    evidence: AlertEvidence = Field(default_factory=AlertEvidence)
    detector_version: str = "1.0.0"
    model_hash: str = ""
    status: Literal["new", "updated", "closed", "anchored"] = "new"
    
    # Optional blockchain / hash chain linkage
    block_index: Optional[int] = None
    tx_hash: Optional[str] = None
    evidence_hash: Optional[str] = None
