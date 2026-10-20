"""
Synthetic Network Flow Generator: Generates realistic benign and intrusion traffic flows
modeled on CIC-IDS2017 / CSE-CIC-IDS2018 datasets for model training and evaluation.
"""
import numpy as np
from typing import Tuple, List, Dict
from features.schema import FEATURE_NAMES, CLASS_TO_ID, ID_TO_CLASS

def generate_flow_dataset(n_samples: int = 5000, random_state: int = 42) -> Tuple[np.ndarray, np.ndarray, List[Dict[str, float]]]:
    """
    Generate balanced dataset with Benign and various attack distributions.
    Returns:
      X: 2D numpy array of shape (n_samples, n_features)
      y: 1D numpy array of integer class labels
      records: list of feature dictionaries
    """
    np.random.seed(random_state)
    per_class = n_samples // 6
    records: List[Dict[str, float]] = []
    labels: List[int] = []

    # 1. BENIGN (Normal Web, DNS, Streaming, SSH)
    for _ in range(per_class):
        duration = float(np.random.exponential(scale=3.5) + 0.1)
        packets = int(np.random.negative_binomial(5, 0.2) + 2)
        avg_pkt_size = float(np.random.normal(520, 150))
        avg_pkt_size = max(64.0, min(1500.0, avg_pkt_size))
        bytes_total = packets * avg_pkt_size
        pps = packets / duration
        bps = bytes_total / duration

        # Well-balanced SYN and ACK handshakes
        syn = int(np.random.choice([1, 2, 3]))
        ack = int(max(syn, np.random.poisson(packets * 0.7)))
        fin = int(np.random.choice([0, 1]))
        rst = int(np.random.choice([0, 0, 0, 1]))
        syn_ack_ratio = float(syn) / float(max(1, ack))

        dst_port = float(np.random.choice([80, 443, 53, 22, 8080, 8443, 3000]))
        proto_num = 6.0 if dst_port != 53 else (17.0 if np.random.rand() > 0.3 else 6.0)
        unique_ports = float(np.random.choice([1, 1, 1, 2]))

        records.append({
            "flow_duration": round(duration, 4),
            "packet_count": float(packets),
            "byte_count": round(bytes_total, 2),
            "packets_per_sec": round(pps, 2),
            "bytes_per_sec": round(bps, 2),
            "avg_packet_size": round(avg_pkt_size, 2),
            "syn_count": float(syn),
            "ack_count": float(ack),
            "fin_count": float(fin),
            "rst_count": float(rst),
            "syn_ack_ratio": round(syn_ack_ratio, 3),
            "dst_port": dst_port,
            "protocol_num": proto_num,
            "unique_dst_ports": unique_ports
        })
        labels.append(CLASS_TO_ID["BENIGN"])

    # 2. PortScan (Rapid scan of numerous ports, low packet count per flow)
    for _ in range(per_class):
        duration = float(np.random.uniform(0.05, 1.2))
        packets = int(np.random.randint(1, 4))
        avg_pkt_size = float(np.random.uniform(40, 64))
        bytes_total = packets * avg_pkt_size
        pps = packets / duration
        bps = bytes_total / duration
        syn = packets
        ack = 0
        syn_ack_ratio = float(syn)
        dst_port = float(np.random.randint(1, 65535))
        unique_ports = float(np.random.randint(10, 80))

        records.append({
            "flow_duration": round(duration, 4),
            "packet_count": float(packets),
            "byte_count": round(bytes_total, 2),
            "packets_per_sec": round(pps, 2),
            "bytes_per_sec": round(bps, 2),
            "avg_packet_size": round(avg_pkt_size, 2),
            "syn_count": float(syn),
            "ack_count": float(ack),
            "fin_count": 0.0,
            "rst_count": float(np.random.choice([0, 1])),
            "syn_ack_ratio": round(syn_ack_ratio, 3),
            "dst_port": dst_port,
            "protocol_num": 6.0,
            "unique_dst_ports": unique_ports
        })
        labels.append(CLASS_TO_ID["PortScan"])

    # 3. SYN_Flood (Massive SYN packets, tiny size, zero/minimal ACK)
    for _ in range(per_class):
        duration = float(np.random.uniform(0.5, 3.0))
        packets = int(np.random.randint(50, 400))
        avg_pkt_size = float(np.random.uniform(40, 60))
        bytes_total = packets * avg_pkt_size
        pps = packets / duration
        bps = bytes_total / duration
        syn = packets
        ack = int(np.random.choice([0, 0, 1]))
        syn_ack_ratio = float(syn) / float(max(1, ack))
        dst_port = float(np.random.choice([80, 443, 8080]))

        records.append({
            "flow_duration": round(duration, 4),
            "packet_count": float(packets),
            "byte_count": round(bytes_total, 2),
            "packets_per_sec": round(pps, 2),
            "bytes_per_sec": round(bps, 2),
            "avg_packet_size": round(avg_pkt_size, 2),
            "syn_count": float(syn),
            "ack_count": float(ack),
            "fin_count": 0.0,
            "rst_count": 0.0,
            "syn_ack_ratio": round(syn_ack_ratio, 3),
            "dst_port": dst_port,
            "protocol_num": 6.0,
            "unique_dst_ports": 1.0
        })
        labels.append(CLASS_TO_ID["SYN_Flood"])

    # 4. ICMP_Flood (High packet rate ICMP echo)
    for _ in range(per_class):
        duration = float(np.random.uniform(0.5, 2.5))
        packets = int(np.random.randint(40, 300))
        avg_pkt_size = float(np.random.uniform(64, 128))
        bytes_total = packets * avg_pkt_size
        pps = packets / duration
        bps = bytes_total / duration

        records.append({
            "flow_duration": round(duration, 4),
            "packet_count": float(packets),
            "byte_count": round(bytes_total, 2),
            "packets_per_sec": round(pps, 2),
            "bytes_per_sec": round(bps, 2),
            "avg_packet_size": round(avg_pkt_size, 2),
            "syn_count": 0.0,
            "ack_count": 0.0,
            "fin_count": 0.0,
            "rst_count": 0.0,
            "syn_ack_ratio": 0.0,
            "dst_port": 0.0,
            "protocol_num": 1.0,
            "unique_dst_ports": 1.0
        })
        labels.append(CLASS_TO_ID["ICMP_Flood"])

    # 5. UDP_Flood (High bandwidth burst, UDP datagrams)
    for _ in range(per_class):
        duration = float(np.random.uniform(0.5, 3.0))
        packets = int(np.random.randint(60, 500))
        avg_pkt_size = float(np.random.uniform(500, 1400))
        bytes_total = packets * avg_pkt_size
        pps = packets / duration
        bps = bytes_total / duration

        records.append({
            "flow_duration": round(duration, 4),
            "packet_count": float(packets),
            "byte_count": round(bytes_total, 2),
            "packets_per_sec": round(pps, 2),
            "bytes_per_sec": round(bps, 2),
            "avg_packet_size": round(avg_pkt_size, 2),
            "syn_count": 0.0,
            "ack_count": 0.0,
            "fin_count": 0.0,
            "rst_count": 0.0,
            "syn_ack_ratio": 0.0,
            "dst_port": float(np.random.choice([53, 123, 5000, 5353])),
            "protocol_num": 17.0,
            "unique_dst_ports": 1.0
        })
        labels.append(CLASS_TO_ID["UDP_Flood"])

    # 6. BruteForce (High frequency attempts against SSH, Web login)
    for _ in range(per_class):
        duration = float(np.random.uniform(1.0, 4.0))
        packets = int(np.random.randint(40, 150))
        avg_pkt_size = float(np.random.uniform(180, 400))
        bytes_total = packets * avg_pkt_size
        pps = packets / duration
        bps = bytes_total / duration
        syn = int(packets * 0.15)
        ack = int(packets * 0.7)
        fin = int(packets * 0.1)
        rst = int(packets * 0.05)
        syn_ack_ratio = float(syn) / float(max(1, ack))

        records.append({
            "flow_duration": round(duration, 4),
            "packet_count": float(packets),
            "byte_count": round(bytes_total, 2),
            "packets_per_sec": round(pps, 2),
            "bytes_per_sec": round(bps, 2),
            "avg_packet_size": round(avg_pkt_size, 2),
            "syn_count": float(syn),
            "ack_count": float(ack),
            "fin_count": float(fin),
            "rst_count": float(rst),
            "syn_ack_ratio": round(syn_ack_ratio, 3),
            "dst_port": float(np.random.choice([22, 80, 443, 3389])),
            "protocol_num": 6.0,
            "unique_dst_ports": 1.0
        })
        labels.append(CLASS_TO_ID["BruteForce"])

    X = np.array([[r[f] for f in FEATURE_NAMES] for r in records], dtype=np.float32)
    y = np.array(labels, dtype=np.int32)
    return X, y, records
