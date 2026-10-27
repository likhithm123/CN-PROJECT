"""
Feature Extractor Module: Converts raw packet counters and flow metrics into
normalized feature vectors for ML models and signature verification.
"""
from typing import Dict, Any, List
import numpy as np
from features.schema import FEATURE_NAMES

class FeatureExtractor:
    @staticmethod
    def extract_features(flow_data: Dict[str, Any], src_stats: Dict[str, Any] = None) -> Dict[str, float]:
        """
        Extract numerical features from flow dictionary and source IP statistics.
        """
        duration = flow_data.get("duration", 0.0)
        packets = flow_data.get("packets", 1)
        bytes_total = flow_data.get("bytes", 0)

        eff_duration = max(1.0, duration) if packets <= 10 else max(0.05, duration)
        packets_per_sec = packets / eff_duration
        bytes_per_sec = bytes_total / eff_duration
        avg_packet_size = bytes_total / max(1, packets)

        syn_count = flow_data.get("syn_count", 0)
        ack_count = flow_data.get("ack_count", 0)
        fin_count = flow_data.get("fin_count", 0)
        rst_count = flow_data.get("rst_count", 0)

        # SYN/ACK ratio: high value indicates half-open SYN flooding
        syn_ack_ratio = float(syn_count) if ack_count == 0 else float(syn_count) / float(ack_count)

        dst_port = float(flow_data.get("dst_port", 0))
        proto = flow_data.get("protocol", "TCP")
        if proto == "TCP":
            proto_num = 6.0
        elif proto == "UDP":
            proto_num = 17.0
        elif proto == "ICMP":
            proto_num = 1.0
        else:
            proto_num = 0.0

        unique_dst_ports = 1.0
        if src_stats and "dst_ports" in src_stats:
            unique_dst_ports = float(len(src_stats["dst_ports"]))

        dns_entropy = float(flow_data.get("dns_entropy", 0.0))
        dns_length = float(flow_data.get("dns_length", 0.0))

        feature_dict = {
            "flow_duration": round(float(duration), 4),
            "packet_count": float(packets),
            "byte_count": float(bytes_total),
            "packets_per_sec": round(float(packets_per_sec), 2),
            "bytes_per_sec": round(float(bytes_per_sec), 2),
            "avg_packet_size": round(float(avg_packet_size), 2),
            "syn_count": float(syn_count),
            "ack_count": float(ack_count),
            "fin_count": float(fin_count),
            "rst_count": float(rst_count),
            "syn_ack_ratio": round(float(syn_ack_ratio), 3),
            "dst_port": dst_port,
            "protocol_num": proto_num,
            "unique_dst_ports": unique_dst_ports,
            "dns_entropy": round(dns_entropy, 3),
            "dns_length": dns_length
        }
        return feature_dict

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy (bits per symbol) of a domain or string."""
        if not text:
            return 0.0
        import math
        counts = {}
        for c in text.lower():
            counts[c] = counts.get(c, 0) + 1
        entropy = 0.0
        length = len(text)
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)


    @staticmethod
    def to_vector(feature_dict: Dict[str, float]) -> np.ndarray:
        """
        Convert feature dictionary to a 1D numpy array aligned with FEATURE_NAMES.
        """
        return np.array([feature_dict.get(k, 0.0) for k in FEATURE_NAMES], dtype=np.float32)

    @staticmethod
    def to_matrix(feature_dicts: List[Dict[str, float]]) -> np.ndarray:
        """
        Convert list of feature dicts to a 2D numpy matrix (samples, features).
        """
        return np.array([[fd.get(k, 0.0) for k in FEATURE_NAMES] for fd in feature_dicts], dtype=np.float32)
