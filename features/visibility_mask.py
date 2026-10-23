"""
Innovation 1: Visibility-Aware AI & Observability Masking Engine.
Addresses the core constraint of unidirectional traffic monitoring through hardware data diodes.
Distinguishes between 'unobserved' and 'did not occur'.
"""

import numpy as np
from typing import Dict, List, Tuple, Any
from ingestion.schema import VisibilityMask, FlowRecord, PacketRecord


FEATURE_NAMES = [
    "packets_per_sec",
    "bytes_per_sec",
    "mean_packet_size",
    "std_packet_size",
    "iat_mean",
    "iat_std",
    "syn_ratio",
    "ack_ratio",
    "fin_ratio",
    "dns_query_count",
    "dns_entropy_max",
    "dns_label_len_max",
    "dns_unique_subdomains",
    "http_incomplete_flag",
    "flow_duration",
    "unique_dst_ports_short",
    "unique_dst_ips_short",
    "periodicity_score",
]

# Physical observability flags in a purely egress/outbound unidirectional diode tap:
# Response metrics (like reverse ack_ratio from server, server replies) are physically unobservable.
UNIDIRECTIONAL_OBSERVABLE_MASK = {
    "packets_per_sec": 1.0,
    "bytes_per_sec": 1.0,
    "mean_packet_size": 1.0,
    "std_packet_size": 1.0,
    "iat_mean": 1.0,
    "iat_std": 1.0,
    "syn_ratio": 1.0,
    "ack_ratio": 0.5,  # Source-side ACKs only (data pushes), NOT server-side ACKs
    "fin_ratio": 1.0,
    "dns_query_count": 1.0,
    "dns_entropy_max": 1.0,
    "dns_label_len_max": 1.0,
    "dns_unique_subdomains": 1.0,
    "http_incomplete_flag": 0.8,  # Can see client not sending body or trailing headers
    "flow_duration": 1.0,
    "unique_dst_ports_short": 1.0,
    "unique_dst_ips_short": 1.0,
    "periodicity_score": 1.0,
}


class VisibilityMaskEngine:
    """
    Manages observability masks and calibrates alert confidence against
    sensor coverage quality.
    """

    def __init__(self, tap_mode: str = "egress_diode"):
        self.tap_mode = tap_mode

    def get_mask_vector(self) -> np.ndarray:
        """Returns binary/weight array indicating feature observability."""
        return np.array([UNIDIRECTIONAL_OBSERVABLE_MASK[name] for name in FEATURE_NAMES], dtype=np.float32)

    def extract_masked_features(
        self,
        raw_features: Dict[str, float],
        visibility: VisibilityMask
    ) -> Tuple[np.ndarray, np.ndarray, float]:
        """
        Extracts feature vector, observability mask vector, and composite visibility quality score.
        Missing/unobservable features are cleanly separated so tree models or neural layers
        do not misinterpret missing server replies as anomalies.
        """
        values = []
        mask_weights = []

        for name in FEATURE_NAMES:
            val = float(raw_features.get(name, 0.0))
            obs_weight = UNIDIRECTIONAL_OBSERVABLE_MASK.get(name, 1.0)
            
            # If tap is unidirectional, downweight unobserved reverse features
            if not visibility.is_reverse_observable and "ack" in name:
                obs_weight *= 0.5

            values.append(val)
            mask_weights.append(obs_weight)

        val_array = np.array(values, dtype=np.float32)
        mask_array = np.array(mask_weights, dtype=np.float32)

        # Calculate overall sensor visibility score (0.0 to 1.0)
        visibility_quality = float(np.mean(mask_array) * visibility.data_quality_score)

        return val_array, mask_array, visibility_quality

    def calibrate_confidence(
        self,
        raw_confidence: float,
        visibility_quality: float,
        threat_type: str
    ) -> Tuple[float, str]:
        """
        Calibrates model alert confidence based on observability quality.
        Generates transparency notes for SOC analysts.
        """
        # Threats that rely strictly on client-side egress (Port scan, SYN flood, DNS tunneling)
        # have very high visibility confidence even on one-way taps.
        # Threats that normally inspect server response (Slowloris response delay) need visibility caveats.
        if threat_type in ["port_scan", "syn_flood", "udp_flood", "dns_tunneling", "c2_beaconing"]:
            factor = 0.85 + (0.15 * visibility_quality)
            note = "High confidence: Threat characteristics reside entirely in observable client-side egress telemetry."
        elif threat_type == "slowloris":
            factor = 0.70 + (0.30 * visibility_quality)
            note = "Moderate confidence: Partial request observed. Server response unobservable over data diode; evaluated via egress header trickle patterns."
        else:
            factor = 0.75 + (0.25 * visibility_quality)
            note = f"Visibility adjusted: Sensor coverage quality rated at {visibility_quality*100:.1f}%."

        calibrated = min(1.0, max(0.05, raw_confidence * factor))
        return round(calibrated, 4), note
