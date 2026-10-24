"""
Unsupervised Anomaly Detector for Unknown Threats for SIH 2026 PS 26145.
Flags behavioral drift outside baseline benign distributions.
Enforces confidence cap below labeled threat detections.
"""

import math
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from schemas.events import Alert, AlertEntities, AlertEvidence


class AnomalyDetector:
    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            config_path = str(Path(__file__).parent / "config.yaml")
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        self.thresholds = self.config.get("thresholds", {})
        self.version = self.config.get("version", "1.0.0")

    def predict(self, features: Dict[str, Any]) -> Optional[Alert]:
        anomaly_score = features.get("anomaly_score", 0.0)
        src_ip = features.get("src_ip", "")
        dst_ip = features.get("dst_ip", "")

        threshold = self.thresholds.get("anomaly_score_threshold", -0.20)
        if anomaly_score >= threshold:
            return None

        # Cap confidence as required by CLAUDE.md
        cap = self.thresholds.get("max_confidence_cap", 0.75)
        raw_conf = min(cap, 0.50 + abs(anomaly_score) * 0.5)

        alert = Alert(
            ts_start=features.get("ts_start", 0.0),
            ts_end=features.get("ts_end", 0.0),
            threat="unclassified_anomaly",
            confidence=round(raw_conf, 4),
            severity="MEDIUM",
            entities=AlertEntities(
                src_ips=[src_ip] if src_ip else [],
                dst_ips=[dst_ip] if dst_ip else [],
                ports=[features.get("dst_port", 0)],
            ),
            evidence=AlertEvidence(
                top_features={
                    "anomaly_score": round(anomaly_score, 4),
                },
                metric_timeseries={"isolation_score": [float(anomaly_score)]},
                sample_flows=[{"src_ip": src_ip, "dst_ip": dst_ip, "score": anomaly_score}],
                rule_hits=[f"Statistical outlier detected by isolation forest (score: {anomaly_score:.3f} < {threshold})"],
            ),
            detector_version=self.version,
            model_hash="sha256:isolation_forest_v1_baseline",
            status="new",
        )
        return alert
