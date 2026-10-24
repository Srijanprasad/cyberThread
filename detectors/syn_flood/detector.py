"""
SYN Flood Detector Plug-in for SIH 2026 PS 26145.
Analyzes forward-only SYN flow rates, SYN-to-ACK ratio, and source entropy.
No reverse-direction packets (SYN-ACK) required or evaluated.
"""

import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from schemas.events import Alert, AlertEntities, AlertEvidence


class SynFloodDetector:
    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            config_path = str(Path(__file__).parent / "config.yaml")
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        self.thresholds = self.config.get("thresholds", {})
        self.version = self.config.get("version", "1.0.0")

    def predict(self, window_features: Dict[str, Any]) -> Optional[Alert]:
        """
        Evaluates 1s window features for SYN flood characteristics.
        """
        syn_count = window_features.get("syn_count", 0)
        syn_ratio = window_features.get("syn_ratio", 0.0)
        pps = window_features.get("pps", 0.0)
        entropy = window_features.get("source_entropy", 0.0)
        dst_ip = window_features.get("dst_ip", "")

        min_syn = self.thresholds.get("min_syn_count", 50)
        min_ratio = self.thresholds.get("min_syn_ratio", 0.85)

        rule_hits = []
        rule_score = 0.0

        if syn_count >= min_syn:
            rule_hits.append(f"Elevated SYN volume ({syn_count} SYNs/sec >= {min_syn})")
            rule_score += 0.45

        if syn_ratio >= min_ratio and syn_count >= 15:
            rule_hits.append(f"Extreme SYN ratio ({syn_ratio*100:.1f}% >= {min_ratio*100:.0f}%)")
            rule_score += 0.40

        if entropy >= self.thresholds.get("entropy_threshold", 0.60):
            rule_hits.append(f"High source entropy ({entropy:.2f} indicates distributed/spoofed sources)")
            rule_score += 0.15

        if rule_score < 0.65:
            return None

        # Calibrated confidence
        confidence = min(1.0, 0.60 + rule_score * 0.40)

        alert = Alert(
            ts_start=window_features.get("ts_start", 0.0),
            ts_end=window_features.get("ts_end", 0.0),
            threat="syn_flood",
            confidence=round(confidence, 4),
            severity="CRITICAL" if pps > 500 else "HIGH",
            entities=AlertEntities(
                dst_ips=[dst_ip],
                ports=[80],
            ),
            evidence=AlertEvidence(
                top_features={
                    "syn_count": float(syn_count),
                    "syn_ratio": round(float(syn_ratio), 4),
                    "pps": round(float(pps), 2),
                    "source_entropy": round(float(entropy), 4),
                },
                metric_timeseries={"syn_rate_pps": [float(pps)]},
                sample_flows=[{"dst_ip": dst_ip, "syn_count": syn_count, "pps": pps}],
                rule_hits=rule_hits,
            ),
            detector_version=self.version,
            model_hash="sha256:syn_flood_v1_rules_calibrated",
            status="new",
        )
        return alert
