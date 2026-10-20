"""
Hybrid Decision / Fusion Engine: Fuses signature-based matching and ML anomaly/classification
into a unified threat assessment using weighted risk scoring and an agreement matrix.
"""
from typing import Dict, Any
from config.settings import (
    FUSION_WEIGHT_SIGNATURE,
    FUSION_WEIGHT_ML,
    THRESHOLD_SUSPICIOUS,
    THRESHOLD_HIGH,
    THRESHOLD_CRITICAL
)

class FusionEngine:
    def __init__(self,
                 weight_signature: float = FUSION_WEIGHT_SIGNATURE,
                 weight_ml: float = FUSION_WEIGHT_ML):
        self.weight_signature = weight_signature
        self.weight_ml = weight_ml

    def fuse(self,
             sig_result: Dict[str, Any],
             anomaly_result: Dict[str, Any],
             classifier_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Synthesize detection outputs into risk score, agreement classification, and recommended action.
        """
        sig_score = float(sig_result.get("score", 0.0))
        sig_detected = bool(sig_result.get("detected", False))

        ml_score = float(anomaly_result.get("anomaly_score", 0.0))
        ml_anomaly = bool(anomaly_result.get("is_anomaly", False))

        rf_class = classifier_result.get("predicted_class", "BENIGN")
        rf_confidence = float(classifier_result.get("confidence", 0.0))

        # 1. Base Weighted Risk Score Calculation
        # Risk = 0.6 * Signature Score + 0.4 * ML Score
        composite_risk = (self.weight_signature * sig_score) + (self.weight_ml * ml_score)

        # 2. Hybrid Agreement Matrix Analysis
        if sig_detected and ml_anomaly:
            # Case 1: High Confidence Attack (Both Agree)
            agreement_type = "HIGH_CONFIDENCE_ATTACK"
            attack_name = sig_result.get("attack", rf_class)
            composite_risk = min(100.0, composite_risk * 1.15)
            action = "RATE_LIMIT" if composite_risk < 80 else "AGGRESSIVE_RATE_LIMIT"
            explanation = f"Signature ({sig_result.get('rule_id')}) and ML Anomaly Detector ({ml_score:.1f}) both verified attack."

        elif sig_detected and not ml_anomaly:
            # Case 2: Signature Triggered, but ML flags normal
            agreement_type = "SUSPICIOUS_HEURISTIC"
            attack_name = f"Suspected {sig_result.get('attack')}"
            action = "MONITOR_FLOW"
            explanation = f"Signature matched {sig_result.get('rule_id')}, but ML anomaly score is low ({ml_score:.1f}). Awaiting further confirmation."

        elif not sig_detected and (ml_score >= 68.0 or (ml_anomaly and rf_class != "BENIGN")):
            # Case 3: Zero-Day / Unknown Anomalous Traffic (Strong ML anomaly, no signature exists)
            agreement_type = "ZERO_DAY_ANOMALY"
            attack_name = f"Zero-Day Anomaly (Likely {rf_class})" if rf_class != "BENIGN" else "Zero-Day Anomalous Traffic Pattern"
            composite_risk = max(composite_risk, ml_score * 0.85)
            action = "RATE_LIMIT" if composite_risk >= 65 else "MONITOR_FLOW"
            explanation = f"Zero-day pattern detected: ML anomaly score {ml_score:.1f} with structural abnormality."

        else:
            # Case 4: Normal Traffic (Both agree normal or benign baseline)
            agreement_type = "BENIGN_CONSENSUS"
            attack_name = "Benign"
            action = "NO_ACTION"
            composite_risk = min(composite_risk, 25.0)
            explanation = "Both signature rules and ML models classify traffic as legitimate."

        composite_risk = round(float(composite_risk), 2)

        # 3. Determine Severity Tier
        if agreement_type == "BENIGN_CONSENSUS":
            severity = "NORMAL"
            final_action = "NO_ACTION"
            is_alert = False
        elif composite_risk >= THRESHOLD_CRITICAL:
            severity = "CRITICAL"
            final_action = "AGGRESSIVE_RATE_LIMIT"
            is_alert = True
        elif composite_risk >= THRESHOLD_HIGH:
            severity = "HIGH"
            final_action = "RATE_LIMIT"
            is_alert = True
        elif composite_risk >= THRESHOLD_SUSPICIOUS:
            severity = "SUSPICIOUS"
            final_action = "MONITOR_FLOW"
            is_alert = True
        else:
            severity = "NORMAL"
            final_action = "NO_ACTION"
            is_alert = False

        return {
            "risk_score": composite_risk,
            "severity": severity,
            "action": final_action,
            "agreement_type": agreement_type,
            "attack_type": attack_name,
            "signature_score": round(sig_score, 1),
            "ml_anomaly_score": round(ml_score, 1),
            "rf_classification": rf_class,
            "rf_confidence": round(rf_confidence, 3),
            "explanation": explanation,
            "is_alert_worthy": is_alert,
            "is_alert": is_alert
        }

