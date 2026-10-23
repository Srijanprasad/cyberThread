"""
Unsupervised Anomaly Detector using Isolation Forest.
Identifies novel zero-day attacks or stealthy behavioral deviations
that do not match predefined supervised signatures.
"""

import os
import joblib
import numpy as np
from typing import Tuple, Optional
from sklearn.ensemble import IsolationForest


class AnomalyDetector:
    """Isolation Forest anomaly detection on normalized feature vectors."""

    def __init__(self, model_path: str = "models/anomaly_detector.joblib"):
        self.model_path = model_path
        self.model: Optional[IsolationForest] = None
        if os.path.exists(self.model_path):
            self.load()

    def load(self):
        """Loads serialized anomaly model."""
        self.model = joblib.load(self.model_path)

    def save(self):
        """Saves trained model."""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)

    def train(self, X_benign: np.ndarray):
        """Fits Isolation Forest on known benign feature vectors."""
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.03,
            random_state=42
        )
        self.model.fit(X_benign)
        self.save()

    def score_anomaly(self, feature_vector: np.ndarray) -> Tuple[bool, float]:
        """
        Calculates anomaly score.
        Returns: (is_anomaly, normalized_anomaly_score from 0.0 to 1.0)
        Higher score = more anomalous.
        """
        if self.model is None:
            return False, 0.0

        vec = feature_vector.reshape(1, -1)
        raw_score = self.model.decision_function(vec)[0]  # lower means more abnormal
        is_outlier = bool(self.model.predict(vec)[0] == -1)

        # Normalize score: decision_function typically in [-0.5, 0.5]
        # Invert so higher score represents higher anomaly
        norm_score = float(np.clip(1.0 - (raw_score + 0.3) / 0.6, 0.0, 1.0))

        return is_outlier, round(norm_score, 4)
