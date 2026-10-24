"""
C2 Beaconing Detector for SIH 2026 PS 26145.
Analyzes unidirectional connection inter-arrival time (IAT) statistics.
Detects periodic check-ins, heartbeats, and jittered intervals.
"""

import math
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from schemas.events import Alert, AlertEntities, AlertEvidence


class C2BeaconDetector:
    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            config_path = str(Path(__file__).parent / "config.yaml")
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        self.thresholds = self.config.get("thresholds", {})
        self.version = self.config.get("version", "1.0.0")

    def predict(self, features: Dict[str, Any]) -> Optional[Alert]:
        event_count = features.get("event_count", 0)
        iat_mean = features.get("iat_mean", 0.0)
        iat_std = features.get("iat_std", 0.0)
        src_ip = features.get("src_ip", "")
        dst_ip = features.get("dst_ip", "")
        dst_port = features.get("dst_port", 8443)

        min_events = self.thresholds.get("min_events", 5)
        if event_count < min_events or iat_mean <= 0.0:
            return None

        # Coefficient of variation (CV) = std / mean
        cv = iat_std / iat_mean if iat_mean > 0 else 1.0

        rule_hits = []
        score = 0.0

        max_cv = self.thresholds.get("max_iat_cv", 0.25)
        if cv <= max_cv:
            rule_hits.append(f"Highly periodic inter-arrival timing (CV: {cv:.3f} <= {max_cv:.2f})")
            score += 0.55

        if iat_mean >= 3.0 and cv <= 0.35:
            rule_hits.append(f"Consistent heartbeat interval of ~{iat_mean:.1f}s observed over {event_count} sessions")
            score += 0.35

        if score < 0.65:
            return None

        confidence = min(1.0, 0.70 + score * 0.30)

        alert = Alert(
            ts_start=features.get("ts_start", 0.0),
            ts_end=features.get("ts_end", 0.0),
            threat="c2_beacon",
            confidence=round(confidence, 4),
            severity="HIGH",
            entities=AlertEntities(
                src_ips=[src_ip] if src_ip else [],
                dst_ips=[dst_ip] if dst_ip else [],
                ports=[dst_port],
            ),
            evidence=AlertEvidence(
                top_features={
                    "iat_mean": round(iat_mean, 2),
                    "iat_std": round(iat_std, 3),
                    "iat_cv": round(cv, 4),
                    "event_count": float(event_count),
                },
                metric_timeseries={"interval_regularity_cv": [float(cv)]},
                sample_flows=[{"src_ip": src_ip, "dst_ip": dst_ip, "interval_mean": iat_mean}],
                rule_hits=rule_hits,
            ),
            detector_version=self.version,
            model_hash="sha256:c2_beacon_v1_stats_calibrated",
            status="new",
        )
        return alert
