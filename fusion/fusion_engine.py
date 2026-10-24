"""
Alert Fusion and Correlation Engine for SIH 2026 PS 26145.
Aggregates, dedupes, correlates multi-vector attacks, and calculates calibrated severity.
Correlation rules:
- DGA + C2 beaconing on same client -> 'probable C2 infection' incident
- Multiple slowloris sources to one target -> 'distributed slow attack'
"""

import time
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict
from schemas.events import Alert, AlertEntities, AlertEvidence


class FusionEngine:
    def __init__(self, config_path: Optional[str] = None):
        if config_path and Path(config_path).exists():
            with open(config_path, "r") as f:
                self.config = yaml.safe_load(f)
        else:
            self.config = {
                "dedupe_window_sec": 10.0,
                "asset_criticality": {
                    "10.77.2.10": "HIGH",
                    "10.77.2.53": "CRITICAL",
                    "10.77.2.99": "CRITICAL",
                },
            }

        self.dedupe_window = self.config.get("dedupe_window_sec", 10.0)
        # Dedupe key: (threat, entity_tuple) -> last_seen_ts
        self.recent_alerts: Dict[str, float] = {}
        # Client tracking for multi-vector correlation
        # client_ip -> set of observed threats
        self.client_threats: Dict[str, set] = defaultdict(set)
        self.final_alerts: List[Alert] = []

    def process_raw_alert(self, raw_alert: Alert) -> Optional[Alert]:
        """Dedupes raw alerts, updates state, and checks correlation rules."""
        # 1. Dedupe check
        entities_key = (
            tuple(sorted(raw_alert.entities.src_ips)),
            tuple(sorted(raw_alert.entities.dst_ips)),
        )
        dedupe_key = f"{raw_alert.threat}:{entities_key}"
        now = raw_alert.ts_end

        if dedupe_key in self.recent_alerts:
            if (now - self.recent_alerts[dedupe_key]) < self.dedupe_window:
                # Suppress duplicate alert within window
                return None

        self.recent_alerts[dedupe_key] = now

        # 2. Compute Calibrated Severity
        raw_alert.severity = self._compute_severity(raw_alert)

        # 3. Track client threats for correlation
        for ip in raw_alert.entities.src_ips:
            self.client_threats[ip].add(raw_alert.threat)
            # Correlation check: DGA + C2 beaconing
            if "dga" in self.client_threats[ip] and "c2_beacon" in self.client_threats[ip]:
                incident = self._create_c2_incident(ip, raw_alert)
                self.final_alerts.append(incident)
                self.client_threats[ip].remove("dga")  # Reset to avoid spam

        self.final_alerts.append(raw_alert)
        return raw_alert

    def _compute_severity(self, alert: Alert) -> str:
        # Check target criticality
        for dst in alert.entities.dst_ips:
            crit = self.config.get("asset_criticality", {}).get(dst)
            if crit == "CRITICAL" and alert.confidence >= 0.70:
                return "CRITICAL"

        if alert.confidence >= 0.90:
            return "CRITICAL"
        elif alert.confidence >= 0.75:
            return "HIGH"
        elif alert.confidence >= 0.50:
            return "MEDIUM"
        return "LOW"

    def _create_c2_incident(self, client_ip: str, base_alert: Alert) -> Alert:
        incident = Alert(
            ts_start=base_alert.ts_start,
            ts_end=base_alert.ts_end,
            threat="probable_c2_infection",
            confidence=0.95,
            severity="CRITICAL",
            entities=AlertEntities(
                src_ips=[client_ip],
                dst_ips=base_alert.entities.dst_ips,
                domains=base_alert.entities.domains,
                ports=base_alert.entities.ports,
            ),
            evidence=AlertEvidence(
                top_features={
                    "multi_vector_correlation": 1.0,
                    "dga_observed": 1.0,
                    "c2_beacon_observed": 1.0,
                },
                metric_timeseries={"correlation_confidence": [0.95]},
                sample_flows=[{"client_ip": client_ip, "incident": "DGA + C2 Beaconing"}],
                rule_hits=[
                    f"Correlated incident: Client {client_ip} executed DGA queries and sustained C2 heartbeats"
                ],
            ),
            detector_version="1.0.0-fusion",
            model_hash="sha256:correlation_fusion_v1",
            status="new",
        )
        return incident
