"""
Supervised Multi-Class Threat Classifier.
Trained on visibility-masked feature vectors for unidirectional traffic enclaves.
"""

import os
import joblib
import numpy as np
from typing import Dict, List, Tuple, Optional
from sklearn.ensemble import RandomForestClassifier

from ingestion.schema import ThreatCategory
from features.visibility_mask import FEATURE_NAMES


CATEGORY_MAP = [
    ThreatCategory.BENIGN.value,
    ThreatCategory.PORT_SCAN.value,
    ThreatCategory.SYN_FLOOD.value,
    ThreatCategory.UDP_FLOOD.value,
    ThreatCategory.SLOWLORIS.value,
    ThreatCategory.DNS_TUNNELING.value,
    ThreatCategory.C2_BEACONING.value,
]


class ThreatClassifier:
    """Supervised threat classification model."""

    def __init__(self, model_path: str = "models/threat_classifier.joblib"):
        self.model_path = model_path
        self.model: Optional[RandomForestClassifier] = None
        self.classes = CATEGORY_MAP
        if os.path.exists(self.model_path):
            self.load()

    def load(self):
        """Loads serialized model from disk."""
        data = joblib.load(self.model_path)
        self.model = data["model"]
        self.classes = data["classes"]

    def save(self):
        """Saves trained model to disk."""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump({"model": self.model, "classes": self.classes}, self.model_path)

    def train(self, X: np.ndarray, y: List[str]):
        """Trains Random Forest model on training feature matrix."""
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=12,
            random_state=42,
            class_weight="balanced"
        )
        self.model.fit(X, y)
        self.classes = list(self.model.classes_)
        self.save()

    def predict(self, feature_vector: np.ndarray) -> Tuple[ThreatCategory, float, Dict[str, float]]:
        """
        Predicts threat category and returns class probabilities.
        """
        if self.model is None:
            # Fallback heuristic if model not yet trained
            return ThreatCategory.BENIGN, 0.5, {c: 0.0 for c in self.classes}

        vec = feature_vector.reshape(1, -1)
        probs = self.model.predict_proba(vec)[0]
        max_idx = int(np.argmax(probs))
        predicted_class_str = self.classes[max_idx]
        confidence = float(probs[max_idx])

        prob_dict = {self.classes[i]: float(probs[i]) for i in range(len(self.classes))}

        try:
            category = ThreatCategory(predicted_class_str)
        except ValueError:
            category = ThreatCategory.BENIGN

        return category, confidence, prob_dict

    def get_feature_importances(self) -> Dict[str, float]:
        """Returns global feature importances from the Random Forest."""
        if self.model is None:
            return {name: 1.0 / len(FEATURE_NAMES) for name in FEATURE_NAMES}
        importances = self.model.feature_importances_
        return {FEATURE_NAMES[i]: float(importances[i]) for i in range(len(FEATURE_NAMES))}
