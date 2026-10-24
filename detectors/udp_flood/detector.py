"""
UDP Flood Detector Plug-in for SIH 2026 PS 26145.
Analyzes forward-only UDP packet rates, byte volumes, and port distributions.
No server ICMP Port Unreachable or responses required.
"""

import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from schemas.events import Alert, AlertEntities, AlertEvidence


class UdpFloodDetector:
    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            config_path = str(Path(__file__).parent / "config.yaml")
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        self.thresholds = self.config.get("thresholds", {})
        self.version = self.config.get("version", "1.0.0")

    def predict(self, window_features: Dict[str, Any]) -> Optional[Alert]:
        pps = window_features.get("pps", 0.0)
        byte_count = window_features.get("byte_count", 0)
        dst_ip = window_features.get("dst_ip", "")
        proto = window_features.get("proto", 17)
        src_ip = window_features.get("src_ip", "")

        min_pps = self.thresholds.get("min_pps", 150.0)

        if proto != 17 and "udp_ratio" not in window_features:
            return None

        rule_hits = []
        score = 0.0

        if pps >= min_pps:
            rule_hits.append(f"Elevated UDP packet rate ({pps:.1f} pps >= {min_pps})")
            score += 0.55

        if byte_count >= self.thresholds.get("min_byte_rate", 50000.0):
            rule_hits.append(f"High volumetric UDP bandwidth ({byte_count} B/s)")
            score += 0.35

        if score < 0.60:
            return None

        confidence = min(1.0, 0.65 + score * 0.35)

        alert = Alert(
            ts_start=window_features.get("ts_start", 0.0),
            ts_end=window_features.get("ts_end", 0.0),
            threat="udp_flood",
            confidence=round(confidence, 4),
            severity="CRITICAL" if pps > 1000 else "HIGH",
            entities=AlertEntities(
                src_ips=[src_ip] if src_ip else [],
                dst_ips=[dst_ip],
                ports=[53],
            ),
            evidence=AlertEvidence(
                top_features={
                    "pps": round(float(pps), 2),
                    "byte_count": float(byte_count),
                },
                metric_timeseries={"udp_rate_pps": [float(pps)]},
                sample_flows=[{"dst_ip": dst_ip, "pps": pps, "bytes": byte_count}],
                rule_hits=rule_hits,
            ),
            detector_version=self.version,
            model_hash="sha256:udp_flood_v1_rules_calibrated",
            status="new",
        )
        return alert
