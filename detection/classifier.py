"""
Supervised Attack Classifier: Uses trained Random Forest model to predict
the specific attack category (PortScan, SYN_Flood, ICMP_Flood, UDP_Flood, BruteForce, Benign).
"""
import joblib
import numpy as np
from pathlib import Path
from typing import Dict, Any, Optional
from config.settings import RANDOM_FOREST_PATH, SCALER_PATH
from features.schema import FEATURE_NAMES, ID_TO_CLASS, ATTACK_CLASSES

class AttackClassifier:
    def __init__(self, model_path: Path = RANDOM_FOREST_PATH, scaler_path: Path = SCALER_PATH):
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.model = None
        self.scaler = None
        self.load_model()

    def load_model(self):
        """Load Random Forest classifier and scaler from disk."""
        if self.model_path.exists() and self.scaler_path.exists():
            try:
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
            except Exception as e:
                print(f"[AttackClassifier] Warning loading models: {e}")
                self.model = None
                self.scaler = None

    def classify_flow(self, feature_dict: Dict[str, float]) -> Dict[str, Any]:
        """Classify flow into specific attack category with confidence probabilities."""
        if self.model is None or self.scaler is None:
            return {
                "predicted_class": "BENIGN",
                "confidence": 0.5,
                "probabilities": {cls: 0.0 for cls in ATTACK_CLASSES}
            }

        vec = np.array([[feature_dict.get(k, 0.0) for k in FEATURE_NAMES]], dtype=np.float32)
        scaled_vec = self.scaler.transform(vec)

        pred_id = int(self.model.predict(scaled_vec)[0])
        pred_label = ID_TO_CLASS.get(pred_id, "BENIGN")

        probs = self.model.predict_proba(scaled_vec)[0]
        prob_dict = {ATTACK_CLASSES[i]: round(float(p), 4) for i, p in enumerate(probs)}
        confidence = float(np.max(probs))

        return {
            "predicted_class": pred_label,
            "confidence": round(confidence, 4),
            "probabilities": prob_dict,
            "is_attack": pred_label != "BENIGN"
        }
