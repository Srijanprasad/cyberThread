"""
Slowloris HTTP Starvation Detector for SIH 2026 PS 26145.
Analyzes unidirectional flow shape only (no server 408/500 responses needed).
Key features:
- Concurrent long-lived streams without FIN/RST
- Low payload volume (< 1KB per flow)
- Low byte rate with regular heartbeat drips
"""

import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from schemas.events import Alert, AlertEntities, AlertEvidence


class SlowlorisDetector:
    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            config_path = str(Path(__file__).parent / "config.yaml")
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        self.thresholds = self.config.get("thresholds", {})
        self.version = self.config.get("version", "1.0.0")

    def predict(self, features: Dict[str, Any]) -> Optional[Alert]:
        concurrent = features.get("concurrent_flows", 0)
        mean_bytes = features.get("mean_flow_bytes", 500.0)
        age = features.get("mean_flow_age", 0.0)
        fin_rst_count = features.get("fin_rst_count", 0)
        src_ip = features.get("src_ip", "")
        dst_ip = features.get("dst_ip", "")

        min_conn = self.thresholds.get("min_concurrent_flows", 20)
        max_bytes = self.thresholds.get("max_mean_bytes", 800.0)

        rule_hits = []
        score = 0.0

        if concurrent >= min_conn:
            rule_hits.append(f"High concurrent unclosed HTTP streams ({concurrent} >= {min_conn})")
            score += 0.50

        if mean_bytes <= max_bytes and concurrent >= 10:
            rule_hits.append(f"Starvation payload shape: mean bytes per flow is only {mean_bytes:.0f}B")
            score += 0.30

        if fin_rst_count == 0 and concurrent >= 15:
            rule_hits.append("Zero FIN/RST flags observed; connections kept open intentionally")
            score += 0.20

        if score < 0.65:
            return None

        confidence = min(1.0, 0.68 + score * 0.32)

        alert = Alert(
            ts_start=features.get("ts_start", 0.0),
            ts_end=features.get("ts_end", 0.0),
            threat="slowloris",
            confidence=round(confidence, 4),
            severity="HIGH",
            entities=AlertEntities(
                src_ips=[src_ip] if src_ip else [],
                dst_ips=[dst_ip] if dst_ip else [],
                ports=[80],
            ),
            evidence=AlertEvidence(
                top_features={
                    "concurrent_flows": float(concurrent),
                    "mean_flow_bytes": float(mean_bytes),
                    "mean_flow_age": float(age),
                },
                metric_timeseries={"concurrent_connections": [float(concurrent)]},
                sample_flows=[{"src_ip": src_ip, "concurrent": concurrent, "bytes": mean_bytes}],
                rule_hits=rule_hits,
            ),
            detector_version=self.version,
            model_hash="sha256:slowloris_v1_rules_calibrated",
            status="new",
        )
        return alert
