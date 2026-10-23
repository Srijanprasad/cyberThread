"""
Rule-Based Heuristic & Change-Point Detection Guardrails.
Provides zero-delay fast-path alerts for high-confidence network anomalies.
"""

from typing import Optional, Dict, Any, Tuple
from ingestion.schema import FlowRecord, ThreatCategory, ThreatSeverity


class RuleDetectionEngine:
    """Fast-path deterministic rule evaluations."""

    def evaluate(
        self,
        flow: FlowRecord,
        temporal_stats: Dict[str, float]
    ) -> Optional[Tuple[ThreatCategory, float, str, ThreatSeverity]]:
        """
        Evaluates rule-based signatures.
        Returns: (threat_category, confidence, rule_description, severity) or None
        """
        # 1. Aggressive or Distributed Port Scan
        # Checks short and medium unique destination ports
        if temporal_stats.get("short_unique_ports", 0) >= 12 or temporal_stats.get("med_unique_ports", 0) >= 20:
            ports_count = int(max(temporal_stats.get("short_unique_ports", 0), temporal_stats.get("med_unique_ports", 0)))
            return (
                ThreatCategory.PORT_SCAN,
                0.95,
                f"Aggressive reconnaissance: {ports_count} unique target ports probed within observation window.",
                ThreatSeverity.HIGH,
            )

        # 2. Volumetric SYN Flood
        # High SYN count or burst of SYN packets from same host in short window
        short_syn = temporal_stats.get("short_syn_pkts", 0)
        if (flow.protocol == "TCP" and flow.syn_count >= 15) or short_syn >= 20:
            return (
                ThreatCategory.SYN_FLOOD,
                0.96,
                f"SYN Flood signature: {max(flow.syn_count, int(short_syn))} SYN packets observed in temporal observation window.",
                ThreatSeverity.CRITICAL,
            )

        # 3. Volumetric UDP Flood
        if flow.protocol == "UDP" and (flow.packets_per_sec > 150 or temporal_stats.get("short_pps", 0) > 150):
            return (
                ThreatCategory.UDP_FLOOD,
                0.94,
                f"UDP Volumetric Flood: Egress surge of {temporal_stats.get('short_pps', 0):.1f} pps targeting port {flow.dst_port}.",
                ThreatSeverity.CRITICAL,
            )

        # 4. DNS Tunneling / Exfiltration (iodine / dnscat2 signature)
        if flow.dns_label_len_max >= 40 or flow.dns_entropy_max >= 3.5 or (flow.dns_unique_subdomains >= 6 and flow.dns_entropy_max >= 3.2):
            return (
                ThreatCategory.DNS_TUNNELING,
                0.97,
                f"DNS Tunneling / Exfiltration: Encoded label length {flow.dns_label_len_max} chars with elevated Shannon entropy ({flow.dns_entropy_max:.2f}).",
                ThreatSeverity.HIGH,
            )

        # 5. Slowloris / HTTP Header Trickle
        # Holding connection open with incomplete header state and long duration
        if flow.http_incomplete and flow.duration >= 8.0 and flow.http_header_count >= 3:
            return (
                ThreatCategory.SLOWLORIS,
                0.88,
                f"Slow HTTP Exhaustion: Incomplete HTTP request holding socket open for {flow.duration:.1f}s with {flow.http_header_count} trickle fragments.",
                ThreatSeverity.MEDIUM,
            )

        # 6. Periodic C2 Beaconing
        if temporal_stats.get("max_beacon_periodicity", 0.0) >= 0.85:
            return (
                ThreatCategory.C2_BEACONING,
                0.90,
                f"C2 Periodic Beaconing: Highly regular outbound check-ins detected (Periodicity Score: {temporal_stats.get('max_beacon_periodicity', 0.0):.2f}).",
                ThreatSeverity.HIGH,
            )

        return None
