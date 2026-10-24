"""
Domain Generation Algorithm (DGA) Detector for SIH 2026 PS 26145.
Analyzes lexical characteristics of query names without NXDOMAIN responses.
Extracts:
- Shannon entropy of domain label
- Vowel-to-consonant ratio
- Longest consecutive consonant run
- Digit ratio
"""

import math
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from schemas.events import Alert, AlertEntities, AlertEvidence


class DgaDetector:
    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            config_path = str(Path(__file__).parent / "config.yaml")
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        self.thresholds = self.config.get("thresholds", {})
        self.version = self.config.get("version", "1.0.0")

    def calc_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        counts = {}
        for c in s:
            counts[c] = counts.get(c, 0) + 1
        n = len(s)
        return -sum((cnt / n) * math.log2(cnt / n) for cnt in counts.values())

    def longest_consonant_run(self, s: str) -> int:
        vowels = set("aeiouAEIOU")
        max_run = 0
        curr_run = 0
        for c in s:
            if c.isalpha() and c not in vowels:
                curr_run += 1
                if curr_run > max_run:
                    max_run = curr_run
            else:
                curr_run = 0
        return max_run

    def predict(self, features: Dict[str, Any]) -> Optional[Alert]:
        qname = features.get("qname", "")
        client_ip = features.get("client_ip", "")
        resolver_ip = features.get("resolver_ip", "")

        parts = qname.split(".")
        label = parts[0] if parts else ""
        n = len(label)

        if n < self.thresholds.get("min_length", 12):
            return None

        entropy = self.calc_entropy(label)
        vowels = sum(1 for c in label if c.lower() in "aeiou")
        vowel_ratio = vowels / n if n > 0 else 0.0
        consonant_run = self.longest_consonant_run(label)
        digit_count = sum(1 for c in label if c.isdigit())
        digit_ratio = digit_count / n if n > 0 else 0.0

        rule_hits = []
        score = 0.0

        if entropy >= self.thresholds.get("min_entropy", 3.20):
            rule_hits.append(f"High lexical randomness (Entropy: {entropy:.2f})")
            score += 0.40

        if vowel_ratio <= self.thresholds.get("max_vowel_ratio", 0.25) or consonant_run >= self.thresholds.get("min_consonant_run", 5):
            rule_hits.append(f"Unnatural consonant distribution (vowel ratio: {vowel_ratio:.2f}, max consonant run: {consonant_run})")
            score += 0.35

        if digit_ratio > 0.20:
            rule_hits.append(f"Elevated digit ratio in domain label ({digit_ratio*100:.1f}%)")
            score += 0.25

        if score < 0.65:
            return None

        confidence = min(1.0, 0.65 + score * 0.35)

        alert = Alert(
            ts_start=features.get("ts", 0.0),
            ts_end=features.get("ts", 0.0),
            threat="dga",
            confidence=round(confidence, 4),
            severity="MEDIUM",
            entities=AlertEntities(
                src_ips=[client_ip] if client_ip else [],
                dst_ips=[resolver_ip] if resolver_ip else [],
                domains=[qname],
                ports=[53],
            ),
            evidence=AlertEvidence(
                top_features={
                    "entropy": round(entropy, 4),
                    "vowel_ratio": round(vowel_ratio, 4),
                    "consonant_run": float(consonant_run),
                    "digit_ratio": round(digit_ratio, 4),
                },
                metric_timeseries={"lexical_entropy": [float(entropy)]},
                sample_flows=[{"qname": qname, "client_ip": client_ip}],
                rule_hits=rule_hits,
            ),
            detector_version=self.version,
            model_hash="sha256:dga_v1_lexical_calibrated",
            status="new",
        )
        return alert
