"""
Multi-Window Behavioral & Ensemble Fusion Layer.
Synthesizes rule guardrails, ML classifier, anomaly detector, and multi-scale temporal state.
"""

from typing import Dict, Any, Tuple, Optional
import numpy as np

from ingestion.schema import FlowRecord, ThreatCategory, ThreatSeverity, VisibilityMask
from detection.rules import RuleDetectionEngine
from detection.classifier import ThreatClassifier
from detection.anomaly_detector import AnomalyDetector
from features.visibility_mask import VisibilityMaskEngine


class ThreatDetectionEnsemble:
    """Ensemble orchestrator fusing all detection modalities."""

    def __init__(
        self,
        classifier: ThreatClassifier,
        anomaly_detector: AnomalyDetector,
        rules: RuleDetectionEngine,
        visibility_engine: VisibilityMaskEngine,
    ):
        self.classifier = classifier
        self.anomaly_detector = anomaly_detector
        self.rules = rules
        self.visibility_engine = visibility_engine

    def evaluate_flow(
        self,
        flow: FlowRecord,
        temporal_stats: Dict[str, float],
        feature_vector: np.ndarray,
        visibility: VisibilityMask,
    ) -> Optional[Dict[str, Any]]:
        """
        Runs complete ensemble evaluation.
        Returns detection decision dict or None if strictly benign.
        """
        # Step 1: Check fast-path deterministic rules
        rule_result = self.rules.evaluate(flow, temporal_stats)
        if rule_result:
            category, conf, description, sev = rule_result
            _, mask_vec, vis_qual = self.visibility_engine.extract_masked_features(
                {}, visibility
            )
            calibrated_conf, vis_notes = self.visibility_engine.calibrate_confidence(
                conf, vis_qual, category.value
            )
            return {
                "category": category,
                "severity": sev,
                "raw_confidence": conf,
                "calibrated_confidence": calibrated_conf,
                "visibility_quality": vis_qual,
                "visibility_notes": vis_notes,
                "detection_layer": "Fast-Path Rule Guardrail",
                "summary": description,
                "rule_matched": True,
            }

        # Step 2: Supervised ML Classifier
        cat_ml, conf_ml, prob_dict = self.classifier.predict(feature_vector)

        # Disallow single-packet SYN flood false positives
        if cat_ml == ThreatCategory.SYN_FLOOD:
            if flow.syn_count < 8 and temporal_stats.get("short_pps", 0) < 25:
                # Not enough volume for a SYN flood, revert to benign or check beaconing
                cat_ml = ThreatCategory.BENIGN
                conf_ml = 0.5

        # Step 3: Unsupervised Anomaly Detector
        is_anomaly, anom_score = self.anomaly_detector.score_anomaly(feature_vector)

        # Step 4: Multi-Window Temporal Fusion
        # If long-window beacon periodicity is elevated (even if single flows are small)
        if temporal_stats.get("max_beacon_periodicity", 0.0) >= 0.70:
            cat_ml = ThreatCategory.C2_BEACONING
            conf_ml = max(conf_ml, temporal_stats["max_beacon_periodicity"])

        # If medium-window port diversity suggests stealth scan
        if temporal_stats.get("med_unique_ports", 0.0) >= 8:
            cat_ml = ThreatCategory.PORT_SCAN
            conf_ml = max(conf_ml, 0.85)

        # Step 5: Check if benign or threat
        is_threat = (cat_ml != ThreatCategory.BENIGN and conf_ml >= 0.60) or (is_anomaly and anom_score >= 0.75)

        if not is_threat:
            return None

        # If ML is benign but anomaly detector caught severe deviation
        final_category = cat_ml
        layer_name = "Supervised Classifier"
        if cat_ml == ThreatCategory.BENIGN and is_anomaly:
            final_category = ThreatCategory.ANOMALY_UNKNOWN
            conf_ml = anom_score
            layer_name = "Zero-Day Anomaly Detector"
        elif temporal_stats.get("max_beacon_periodicity", 0.0) >= 0.70 or temporal_stats.get("med_unique_ports", 0.0) >= 8:
            layer_name = "Multi-Window Behavioral Fusion"

        _, _, vis_qual = self.visibility_engine.extract_masked_features({}, visibility)
        calibrated_conf, vis_notes = self.visibility_engine.calibrate_confidence(
            conf_ml, vis_qual, final_category.value
        )

        # Assign severity based on calibrated confidence and threat type
        severity = ThreatSeverity.MEDIUM
        if final_category in [ThreatCategory.SYN_FLOOD, ThreatCategory.UDP_FLOOD]:
            severity = ThreatSeverity.CRITICAL if calibrated_conf > 0.85 else ThreatSeverity.HIGH
        elif final_category in [ThreatCategory.C2_BEACONING, ThreatCategory.DNS_TUNNELING, ThreatCategory.PORT_SCAN]:
            severity = ThreatSeverity.HIGH if calibrated_conf > 0.80 else ThreatSeverity.MEDIUM
        elif final_category == ThreatCategory.SLOWLORIS:
            severity = ThreatSeverity.MEDIUM

        return {
            "category": final_category,
            "severity": severity,
            "raw_confidence": conf_ml,
            "calibrated_confidence": calibrated_conf,
            "visibility_quality": vis_qual,
            "visibility_notes": vis_notes,
            "detection_layer": layer_name,
            "summary": f"Detected {final_category.value.replace('_', ' ').title()} via {layer_name}.",
            "rule_matched": False,
            "anomaly_score": anom_score,
            "probabilities": prob_dict,
        }
