"""
Automated Test Suite for Hybrid NIDS and Adaptive QoS Mitigation.
Validates Feature Extraction, Signature Matching, ML Anomaly Inference,
Decision Fusion, QoS Feedback Loop, and Alert Persistence.
"""
import unittest
import time
import numpy as np
from pathlib import Path

from capture.flow_manager import FlowManager
from features.extractor import FeatureExtractor
from detection.signature_engine import SignatureEngine
from detection.anomaly_detector import AnomalyDetector
from detection.classifier import AttackClassifier
from decision.fusion_engine import FusionEngine
from mitigation.qos_controller import QoSController
from alerts.alert_manager import AlertManager

class TestHybridNIDS(unittest.TestCase):

    def setUp(self):
        self.flow_mgr = FlowManager(timeout_seconds=5.0)
        self.sig_engine = SignatureEngine()
        self.anomaly_detector = AnomalyDetector()
        self.classifier = AttackClassifier()
        self.fusion = FusionEngine()
        self.qos = QoSController(cooldown_seconds=1.0)
        self.test_db = Path("test_alerts.db")
        self.alert_mgr = AlertManager(db_path=self.test_db)

    def tearDown(self):
        if self.test_db.exists():
            try:
                self.test_db.unlink()
            except Exception:
                pass

    def test_feature_extraction(self):
        # Add normal packets to flow manager
        for _ in range(10):
            self.flow_mgr.add_packet("10.0.0.1", "10.0.0.2", 50000, 80, "TCP", 100, {"A": True})

        flows = self.flow_mgr.get_active_flows()
        self.assertEqual(len(flows), 1)
        features = FeatureExtractor.extract_features(flows[0])

        self.assertIn("packets_per_sec", features)
        self.assertIn("syn_ack_ratio", features)
        self.assertEqual(features["dst_port"], 80.0)
        self.assertEqual(features["protocol_num"], 6.0)

    def test_signature_syn_flood(self):
        flow = {
            "protocol": "TCP",
            "dst_port": 80,
            "packets": 50,
            "bytes": 2700,
            "syn_count": 50,
            "ack_count": 0
        }
        features = {
            "flow_duration": 1.0,
            "packets_per_sec": 50.0,
            "bytes_per_sec": 2700.0,
            "syn_ack_ratio": 50.0,
            "unique_dst_ports": 1.0
        }
        res = self.sig_engine.evaluate(flow, features)
        self.assertTrue(res["detected"])
        self.assertEqual(res["rule_id"], "SIG-002")
        self.assertEqual(res["severity"], "CRITICAL")

    def test_signature_port_scan(self):
        flow = {
            "protocol": "TCP",
            "dst_port": 443,
            "packets": 15,
            "syn_count": 15,
            "ack_count": 0
        }
        features = {
            "flow_duration": 0.5,
            "packets_per_sec": 30.0,
            "bytes_per_sec": 1200.0,
            "syn_ack_ratio": 15.0,
            "unique_dst_ports": 12.0
        }
        res = self.sig_engine.evaluate(flow, features)
        self.assertTrue(res["detected"])
        self.assertEqual(res["rule_id"], "SIG-001")

    def test_ml_anomaly_detection(self):
        # Benign flow features
        benign_features = {
            "flow_duration": 3.0,
            "packet_count": 15.0,
            "byte_count": 7500.0,
            "packets_per_sec": 5.0,
            "bytes_per_sec": 2500.0,
            "avg_packet_size": 500.0,
            "syn_count": 2.0,
            "ack_count": 12.0,
            "fin_count": 1.0,
            "rst_count": 0.0,
            "syn_ack_ratio": 0.166,
            "dst_port": 443.0,
            "protocol_num": 6.0,
            "unique_dst_ports": 1.0
        }
        res_benign = self.anomaly_detector.score_flow(benign_features)
        self.assertLess(res_benign["anomaly_score"], 60.0)

        # Extreme anomaly features (SYN flood blast)
        anomaly_features = {
            "flow_duration": 0.8,
            "packet_count": 200.0,
            "byte_count": 10800.0,
            "packets_per_sec": 250.0,
            "bytes_per_sec": 13500.0,
            "avg_packet_size": 54.0,
            "syn_count": 200.0,
            "ack_count": 0.0,
            "fin_count": 0.0,
            "rst_count": 0.0,
            "syn_ack_ratio": 200.0,
            "dst_port": 80.0,
            "protocol_num": 6.0,
            "unique_dst_ports": 1.0
        }
        res_anomaly = self.anomaly_detector.score_flow(anomaly_features)
        self.assertGreater(res_anomaly["anomaly_score"], 60.0)

    def test_decision_fusion_cases(self):
        # Case 1: High Confidence Attack (Signature + ML agree)
        sig_case1 = {"detected": True, "rule_id": "SIG-002", "attack": "TCP SYN Flood", "score": 95.0}
        ml_case1 = {"is_anomaly": True, "anomaly_score": 90.0}
        rf_case1 = {"predicted_class": "SYN_Flood", "confidence": 0.99}
        decision1 = self.fusion.fuse(sig_case1, ml_case1, rf_case1)
        self.assertEqual(decision1["agreement_type"], "HIGH_CONFIDENCE_ATTACK")
        self.assertEqual(decision1["severity"], "CRITICAL")
        self.assertGreaterEqual(decision1["risk_score"], 80.0)

        # Case 3: Zero-Day Anomaly (Signature says normal, ML flags high anomaly)
        sig_case3 = {"detected": False, "rule_id": None, "score": 0.0}
        ml_case3 = {"is_anomaly": True, "anomaly_score": 85.0}
        rf_case3 = {"predicted_class": "BENIGN", "confidence": 0.4}
        decision3 = self.fusion.fuse(sig_case3, ml_case3, rf_case3)
        self.assertEqual(decision3["agreement_type"], "ZERO_DAY_ANOMALY")
        self.assertIn(decision3["severity"], ["HIGH", "CRITICAL", "SUSPICIOUS"])

    def test_qos_mitigation_and_feedback_loop(self):
        ip = "192.168.1.150"
        # 1. Apply Critical mitigation
        policy = self.qos.apply_mitigation(ip, risk_score=92.0, attack_type="SYN Flood", severity="CRITICAL")
        self.assertEqual(policy["tier"], "CRITICAL")
        self.assertEqual(policy["rate_limit_mbps"], 0.25)

        # 2. Wait past cooldown threshold and run feedback loop
        time.sleep(1.1)
        actions = self.qos.process_feedback_loop()
        self.assertTrue(len(actions) > 0)
        self.assertEqual(actions[0]["previous_tier"], "CRITICAL")
        self.assertEqual(actions[0]["new_tier"], "HIGH")

        # 3. Next cooldown step down
        time.sleep(1.1)
        actions2 = self.qos.process_feedback_loop()
        self.assertEqual(actions2[0]["previous_tier"], "HIGH")
        self.assertEqual(actions2[0]["new_tier"], "SUSPICIOUS")

    def test_alert_persistence(self):
        alert = self.alert_mgr.create_alert(
            source_ip="10.0.2.15",
            destination_ip="10.0.2.30",
            source_port=45000,
            destination_port=80,
            protocol="TCP",
            attack_type="SYN Flood",
            signature_result="SIG-002",
            ml_result="ANOMALY",
            risk_score=94.5,
            severity="CRITICAL",
            action="AGGRESSIVE_RATE_LIMIT"
        )
        self.assertIsNotNone(alert)
        alerts = self.alert_mgr.get_recent_alerts(limit=5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["source_ip"], "10.0.2.15")
        self.assertEqual(alerts[0]["severity"], "CRITICAL")

    def test_shannon_entropy(self):
        # Regular English domain: lower entropy (~2.5 - 3.0)
        h_normal = FeatureExtractor.calculate_shannon_entropy("google.com")
        self.assertLess(h_normal, 3.2)

        # High-entropy hex/base64 encoded exfiltration subdomain (> 3.5)
        h_exf = FeatureExtractor.calculate_shannon_entropy("a8f3b9c41d7e2650ba99ef014ca982d3.attacker.com")
        self.assertGreater(h_exf, 3.5)

    def test_sig_007_dns_tunneling(self):
        flow = {
            "protocol": "UDP",
            "dst_port": 53,
            "packets": 5,
            "bytes": 600,
            "dns_entropy": 3.85,
            "dns_length": 45.0
        }
        features = {
            "flow_duration": 0.2,
            "packets_per_sec": 25.0,
            "bytes_per_sec": 3000.0,
            "dns_entropy": 3.85,
            "dns_length": 45.0,
            "dst_port": 53.0
        }
        res = self.sig_engine.evaluate(flow, features)
        self.assertTrue(res["detected"])
        self.assertEqual(res["rule_id"], "SIG-007")

    def test_pcap_analyzer_sample(self):
        from capture.pcap_analyzer import PCAPAnalyzer
        analyzer = PCAPAnalyzer()
        res = analyzer.analyze_file("uploads/sample_pcaps/wireshark_dns_attack.pcapng")
        self.assertEqual(res["status"], "success")
        self.assertGreaterEqual(res["packets_analyzed"], 1)
        self.assertGreaterEqual(res["threats_detected_count"], 1)

if __name__ == "__main__":
    unittest.main()

