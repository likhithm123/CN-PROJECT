"""
Anomaly Detector: Uses trained Isolation Forest to score flow anomalies (0 - 100).
Trained on normal/benign network traffic; high score indicates anomalous / unseen behavior.
"""
import joblib
import numpy as np
from pathlib import Path
from typing import Dict, Any, Optional
from config.settings import ISOLATION_FOREST_PATH, SCALER_PATH
from features.schema import FEATURE_NAMES

class AnomalyDetector:
    def __init__(self, model_path: Path = ISOLATION_FOREST_PATH, scaler_path: Path = SCALER_PATH):
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.model = None
        self.scaler = None
        self.load_model()

    def load_model(self):
        """Load Isolation Forest and feature scaler from disk."""
        if self.model_path.exists() and self.scaler_path.exists():
            try:
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
            except Exception as e:
                print(f"[AnomalyDetector] Warning loading models: {e}")
                self.model = None
                self.scaler = None

    def score_flow(self, feature_dict: Dict[str, float]) -> Dict[str, Any]:
        """
        Calculates an anomaly score between 0.0 (strictly benign) and 100.0 (extreme anomaly).
        """
        if self.model is None or self.scaler is None:
            # Fallback heuristic if models are not yet trained
            pps = feature_dict.get("packets_per_sec", 0)
            syn_ack = feature_dict.get("syn_ack_ratio", 0)
            ports = feature_dict.get("unique_dst_ports", 1)
            heuristic_score = min(100.0, (pps / 10.0) + (syn_ack * 5.0) + (ports * 2.0))
            return {
                "anomaly_score": round(heuristic_score, 2),
                "is_anomaly": heuristic_score > 60.0,
                "confidence": round(min(1.0, heuristic_score / 100.0), 3),
                "model_status": "heuristic_fallback"
            }

        vec = np.array([[feature_dict.get(k, 0.0) for k in FEATURE_NAMES]], dtype=np.float32)
        scaled_vec = self.scaler.transform(vec)

        # decision_function: negative is anomaly, positive is normal
        # Typical range: approx -0.3 to +0.3
        raw_score = float(self.model.decision_function(scaled_vec)[0])
        prediction = int(self.model.predict(scaled_vec)[0]) # 1: normal, -1: anomaly

        # Map raw_score to 0 - 100 scale:
        # raw_score <= -0.15 -> ~100
        # raw_score >= 0.15 -> ~0
        # Sigmoid-like transformation
        normalized_score = 100.0 / (1.0 + np.exp(12.0 * raw_score))
        normalized_score = float(np.clip(normalized_score, 0.0, 100.0))

        is_anomaly = (prediction == -1) or (normalized_score > 55.0)
        confidence = float(min(1.0, max(0.0, abs(raw_score) / 0.25)))

        return {
            "anomaly_score": round(normalized_score, 2),
            "raw_decision_score": round(raw_score, 4),
            "is_anomaly": is_anomaly,
            "confidence": round(confidence, 3),
            "model_status": "trained_isolation_forest"
        }
