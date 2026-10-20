"""
PCAP & PCAPNG File Analyzer:
Enables offline forensics and batch ingestion of network packet traces
captured via Wireshark, tcpdump, or public intrusion benchmarks.
"""
import os
import time
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from scapy.all import PcapReader, PcapNgReader, IP, TCP, UDP, ICMP

from capture.flow_manager import FlowManager
from features.extractor import FeatureExtractor
from detection.signature_engine import SignatureEngine
from detection.anomaly_detector import AnomalyDetector
from detection.classifier import AttackClassifier
from decision.fusion_engine import FusionEngine
from mitigation.qos_controller import QoSController
from alerts.alert_manager import AlertManager

logger = logging.getLogger("PCAPAnalyzer")

class PCAPAnalyzer:
    def __init__(self,
                 sig_engine: Optional[SignatureEngine] = None,
                 anomaly_detector: Optional[AnomalyDetector] = None,
                 classifier: Optional[AttackClassifier] = None,
                 fusion_engine: Optional[FusionEngine] = None,
                 alert_manager: Optional[AlertManager] = None):
        self.sig_engine = sig_engine or SignatureEngine()
        self.anomaly_detector = anomaly_detector or AnomalyDetector()
        self.classifier = classifier or AttackClassifier()
        self.fusion = fusion_engine or FusionEngine()
        self.alert_manager = alert_manager or AlertManager()

    def analyze_file(self, file_path: str, max_packets: int = 25000) -> Dict[str, Any]:
        """
        Parse a .pcap or .pcapng file, extract network flows, run hybrid detection,
        and generate a forensic security report.
        """
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"PCAP file not found: {file_path}")

        file_ext = p.suffix.lower()
        file_size_bytes = p.stat().st_size

        flow_mgr = FlowManager(timeout_seconds=3600.0) # long timeout for batch trace
        packets_read = 0
        dns_packets = 0
        start_ts = None
        end_ts = None

        # Choose appropriate Scapy reader
        reader = None
        is_pcapng = False
        try:
            if file_ext in [".pcapng", ".ntar"]:
                is_pcapng = True
                reader = PcapNgReader(str(p))
            else:
                reader = PcapReader(str(p))
        except Exception as e:
            # Fallback attempt
            try:
                reader = PcapNgReader(str(p))
                is_pcapng = True
            except Exception:
                reader = PcapReader(str(p))

        try:
            for pkt in reader:
                packets_read += 1
                if max_packets and packets_read > max_packets:
                    break

                if not pkt.haslayer(IP):
                    continue

                ip_layer = pkt[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                pkt_len = len(pkt)
                ts = float(pkt.time) if hasattr(pkt, "time") else time.time()

                if start_ts is None or ts < start_ts:
                    start_ts = ts
                if end_ts is None or ts > end_ts:
                    end_ts = ts

                src_port = 0
                dst_port = 0
                protocol = "OTHER"
                tcp_flags = None

                if pkt.haslayer(TCP):
                    tcp_layer = pkt[TCP]
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    protocol = "TCP"
                    flags = tcp_layer.flags
                    tcp_flags = {
                        "S": bool(flags & 0x02),
                        "A": bool(flags & 0x10),
                        "F": bool(flags & 0x01),
                        "R": bool(flags & 0x04),
                        "P": bool(flags & 0x08),
                        "U": bool(flags & 0x20)
                    }
                elif pkt.haslayer(UDP):
                    udp_layer = pkt[UDP]
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport
                    protocol = "UDP"
                elif pkt.haslayer(ICMP):
                    protocol = "ICMP"

                # DNS inspection
                dns_entropy = 0.0
                dns_length = 0.0
                if pkt.haslayer("DNS"):
                    dns_packets += 1
                    try:
                        dns_layer = pkt.getlayer("DNS")
                        if dns_layer and hasattr(dns_layer, "qd") and dns_layer.qd:
                            qname = dns_layer.qd.qname
                            qname_str = qname.decode("utf-8", errors="ignore").rstrip(".") if isinstance(qname, bytes) else str(qname).rstrip(".")
                            dns_length = float(len(qname_str))
                            dns_entropy = FeatureExtractor.calculate_shannon_entropy(qname_str)
                    except Exception:
                        pass

                flow_mgr.add_packet(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    pkt_len=pkt_len,
                    tcp_flags=tcp_flags,
                    timestamp=ts,
                    dns_entropy=dns_entropy,
                    dns_length=dns_length
                )
        finally:
            if hasattr(reader, "close"):
                reader.close()

        # Run detection across all assembled flows
        active_flows = flow_mgr.get_active_flows()
        detected_threats = []
        high_risk_ips = set()
        agreement_breakdown = {
            "HIGH_CONFIDENCE_ATTACK": 0,
            "ZERO_DAY_ANOMALY": 0,
            "SUSPICIOUS_HEURISTIC": 0,
            "BENIGN_CONSENSUS": 0
        }

        for flow in active_flows:
            src_ip = flow["src_ip"]
            src_stats = flow_mgr.src_stats.get(src_ip)
            features = FeatureExtractor.extract_features(flow, src_stats)

            sig_res = self.sig_engine.evaluate(flow, features, src_stats)
            anom_res = self.anomaly_detector.score_flow(features)
            class_res = self.classifier.classify_flow(features)
            decision = self.fusion.fuse(sig_res, anom_res, class_res)

            agr_type = decision.get("agreement_type", "BENIGN_CONSENSUS")
            if agr_type in agreement_breakdown:
                agreement_breakdown[agr_type] += 1

            if decision["is_alert"]:
                high_risk_ips.add(src_ip)
                threat_info = {
                    "source_ip": src_ip,
                    "destination_ip": flow["dst_ip"],
                    "protocol": flow["protocol"],
                    "destination_port": flow["dst_port"],
                    "attack_type": decision["attack_type"],
                    "rule_id": sig_res.get("rule_id"),
                    "risk_score": decision["risk_score"],
                    "severity": decision["severity"],
                    "agreement_type": agr_type,
                    "action": decision["action"],
                    "anomaly_score": anom_res["anomaly_score"],
                    "explanation": decision["explanation"]
                }
                detected_threats.append(threat_info)

                # Persist to database
                if self.alert_manager:
                    self.alert_manager.create_alert(
                        source_ip=src_ip,
                        destination_ip=flow["dst_ip"],
                        source_port=flow["src_port"],
                        destination_port=flow["dst_port"],
                        protocol=flow["protocol"],
                        attack_type=decision["attack_type"],
                        signature_result=sig_res.get("rule_id") or "NONE",
                        ml_result=f"ANOMALY ({anom_res['anomaly_score']:.1f})" if anom_res["is_anomaly"] else "NORMAL",
                        risk_score=decision["risk_score"],
                        severity=decision["severity"],
                        action=decision["action"],
                        details=f"[PCAP: {p.name}] {decision['explanation']}"
                    )

        duration_sec = max(0.001, (end_ts - start_ts)) if (start_ts and end_ts) else 0.0

        return {
            "status": "success",
            "filename": p.name,
            "format": "PCAPNG (Wireshark Next Generation)" if is_pcapng else "Standard PCAP (libpcap)",
            "file_size_kb": round(file_size_bytes / 1024.0, 2),
            "packets_analyzed": packets_read,
            "dns_packets_count": dns_packets,
            "flows_reconstructed": len(active_flows),
            "trace_duration_seconds": round(duration_sec, 2),
            "threats_detected_count": len(detected_threats),
            "high_risk_ips": list(high_risk_ips),
            "agreement_breakdown": agreement_breakdown,
            "threats": detected_threats[:50] # Top 50 threats for responsive display
        }
