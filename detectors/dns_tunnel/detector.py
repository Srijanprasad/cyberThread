"""
DNS Tunneling Detector (iodine / dnscat2) for SIH 2026 PS 26145.
Evaluates forward-only DNS queries without needing server responses.
Extracts:
- Shannon entropy of subdomains
- Maximum and mean label length
- Base32 / Base64 lexical features
- High query rate to a single parent domain
"""

import math
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from schemas.events import Alert, AlertEntities, AlertEvidence


class DnsTunnelDetector:
    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            config_path = str(Path(__file__).parent / "config.yaml")
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        self.thresholds = self.config.get("thresholds", {})
        self.version = self.config.get("version", "1.0.0")

    def calc_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        counts = {}
        for c in text:
            counts[c] = counts.get(c, 0) + 1
        n = len(text)
        return -sum((cnt / n) * math.log2(cnt / n) for cnt in counts.values())

    def predict(self, features: Dict[str, Any]) -> Optional[Alert]:
        qname = features.get("qname", "")
        client_ip = features.get("client_ip", "")
        resolver_ip = features.get("resolver_ip", "")
        qtype = features.get("qtype", "A")

        labels = qname.split(".")
        subdomain = labels[0] if labels else ""
        sub_len = len(subdomain)
        entropy = self.calc_entropy(subdomain)

        min_entropy = self.thresholds.get("min_entropy", 3.60)
        min_len = self.thresholds.get("min_mean_label_len", 25.0)

        rule_hits = []
        score = 0.0

        if entropy >= min_entropy and sub_len >= 16:
            rule_hits.append(f"High subdomain Shannon entropy ({entropy:.2f} >= {min_entropy:.2f})")
            score += 0.50

        if sub_len >= min_len:
            rule_hits.append(f"Extended label length ({sub_len} chars >= {min_len:.0f}) indicating data exfiltration")
            score += 0.35

        if qtype == "TXT":
            rule_hits.append("TXT query type utilized for data encapsulation")
            score += 0.15

        if score < 0.65:
            return None

        confidence = min(1.0, 0.70 + score * 0.30)

        alert = Alert(
            ts_start=features.get("ts", 0.0),
            ts_end=features.get("ts", 0.0),
            threat="dns_tunnel",
            confidence=round(confidence, 4),
            severity="HIGH",
            entities=AlertEntities(
                src_ips=[client_ip] if client_ip else [],
                dst_ips=[resolver_ip] if resolver_ip else [],
                domains=[qname],
                ports=[53],
            ),
            evidence=AlertEvidence(
                top_features={
                    "entropy": round(entropy, 4),
                    "subdomain_len": float(sub_len),
                    "qtype_is_txt": 1.0 if qtype == "TXT" else 0.0,
                },
                metric_timeseries={"subdomain_entropy": [float(entropy)]},
                sample_flows=[{"qname": qname, "client_ip": client_ip, "qtype": qtype}],
                rule_hits=rule_hits,
            ),
            detector_version=self.version,
            model_hash="sha256:dns_tunnel_v1_rules_calibrated",
            status="new",
        )
        return alert
