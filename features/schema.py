"""
Feature definitions and schema for NIDS anomaly detection and classification.
Aligned with CIC-IDS2017 flow characteristics.
"""

FEATURE_NAMES = [
    "flow_duration",          # Flow lifetime in seconds
    "packet_count",           # Total packets in flow
    "byte_count",             # Total bytes transferred
    "packets_per_sec",        # Packet throughput
    "bytes_per_sec",          # Byte throughput
    "avg_packet_size",        # Average payload/packet size
    "syn_count",              # Count of SYN flags
    "ack_count",              # Count of ACK flags
    "fin_count",              # Count of FIN flags
    "rst_count",              # Count of RST flags
    "syn_ack_ratio",          # Ratio of SYN to ACK (floods have high ratio)
    "dst_port",               # Destination port number
    "protocol_num",           # 6=TCP, 17=UDP, 1=ICMP
    "unique_dst_ports"        # Number of unique destination ports accessed by src IP in window
]

# Attack Labels for Supervised Classification
ATTACK_CLASSES = [
    "BENIGN",
    "PortScan",
    "SYN_Flood",
    "ICMP_Flood",
    "UDP_Flood",
    "BruteForce",
    "DNS_Exfiltration"
]


CLASS_TO_ID = {name: i for i, name in enumerate(ATTACK_CLASSES)}
ID_TO_CLASS = {i: name for i, name in enumerate(ATTACK_CLASSES)}
