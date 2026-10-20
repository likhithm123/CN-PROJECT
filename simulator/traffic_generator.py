"""
Traffic Generator & Attack Simulator:
Simulates realistic background traffic and can inject attack scenarios (PortScan,
SYN Flood, ICMP Flood, UDP Flood, Zero-Day Anomaly) on demand for testing and live demonstrations.
"""
import time
import random
import threading
import logging
from typing import Optional, Callable
from capture.packet_capture import PacketCapture

logger = logging.getLogger("TrafficGenerator")

class TrafficGenerator:
    def __init__(self, packet_capture: PacketCapture):
        self.packet_capture = packet_capture
        self.is_background_running = False
        self._bg_thread: Optional[threading.Thread] = None

        # Sample pool of legitimate internal and external IPs
        self.legit_clients = ["10.0.2.100", "10.0.2.101", "10.0.2.102", "192.168.1.50"]
        self.victim_servers = ["10.0.2.30", "10.0.2.40"]

    def start_background_benign_traffic(self, delay_range: tuple = (0.3, 1.0)):
        """Continuously generate legitimate web, DNS, and SSH traffic."""
        if self.is_background_running:
            return
        self.is_background_running = True

        def bg_worker():
            while self.is_background_running:
                client = random.choice(self.legit_clients)
                server = random.choice(self.victim_servers)
                flow_type = random.choice(["HTTP", "HTTPS", "DNS", "SSH"])

                if flow_type == "HTTP":
                    sport = random.randint(30000, 60000)
                    dport = 80
                    # 3-way handshake + small exchange
                    self.packet_capture.inject_synthetic_packet(client, server, sport, dport, "TCP", 64, {"S": True})
                    self.packet_capture.inject_synthetic_packet(server, client, dport, sport, "TCP", 64, {"S": True, "A": True})
                    self.packet_capture.inject_synthetic_packet(client, server, sport, dport, "TCP", 54, {"A": True})
                    self.packet_capture.inject_synthetic_packet(client, server, sport, dport, "TCP", random.randint(300, 1200), {"P": True, "A": True})
                    self.packet_capture.inject_synthetic_packet(server, client, dport, sport, "TCP", 54, {"A": True})

                elif flow_type == "HTTPS":
                    sport = random.randint(30000, 60000)
                    dport = 443
                    self.packet_capture.inject_synthetic_packet(client, server, sport, dport, "TCP", 64, {"S": True})
                    self.packet_capture.inject_synthetic_packet(server, client, dport, sport, "TCP", 64, {"S": True, "A": True})
                    self.packet_capture.inject_synthetic_packet(client, server, sport, dport, "TCP", random.randint(500, 1400), {"A": True})

                elif flow_type == "DNS":
                    sport = random.randint(30000, 60000)
                    dport = 53
                    self.packet_capture.inject_synthetic_packet(client, "8.8.8.8", sport, dport, "UDP", random.randint(60, 120))
                    self.packet_capture.inject_synthetic_packet("8.8.8.8", client, dport, sport, "UDP", random.randint(80, 250))

                time.sleep(random.uniform(*delay_range))

        self._bg_thread = threading.Thread(target=bg_worker, daemon=True)
        self._bg_thread.start()

    def stop_background_benign_traffic(self):
        self.is_background_running = False

    def simulate_port_scan(self, attacker_ip: str = "10.0.2.15", target_ip: str = "10.0.2.30", count: int = 15):
        """Simulate rapid TCP SYN port scan (SIG-001)."""
        logger.info(f"Triggering Port Scan from {attacker_ip} -> {target_ip}")
        target_ports = random.sample(range(20, 1024), count)
        for port in target_ports:
            sport = random.randint(40000, 65000)
            self.packet_capture.inject_synthetic_packet(
                src_ip=attacker_ip,
                dst_ip=target_ip,
                src_port=sport,
                dst_port=port,
                protocol="TCP",
                pkt_len=44,
                tcp_flags={"S": True}
            )
            time.sleep(0.02)

    def simulate_syn_flood(self, attacker_ip: str = "10.0.2.18", target_ip: str = "10.0.2.30", packet_count: int = 50):
        """Simulate TCP SYN Flood attack without ACK handshakes (SIG-002)."""
        logger.info(f"Triggering SYN Flood from {attacker_ip} -> {target_ip}")
        target_port = 80
        # Concentrate over a few source ports to simulate realistic volumetric burst
        ports_pool = [44100, 44101, 44102]
        for _ in range(packet_count):
            sport = random.choice(ports_pool)
            self.packet_capture.inject_synthetic_packet(
                src_ip=attacker_ip,
                dst_ip=target_ip,
                src_port=sport,
                dst_port=target_port,
                protocol="TCP",
                pkt_len=54,
                tcp_flags={"S": True}
            )
            time.sleep(0.005)

    def simulate_icmp_flood(self, attacker_ip: str = "10.0.2.25", target_ip: str = "10.0.2.30", packet_count: int = 40):
        """Simulate ICMP Flood / Ping of Death burst (SIG-003)."""
        logger.info(f"Triggering ICMP Flood from {attacker_ip} -> {target_ip}")
        for _ in range(packet_count):
            self.packet_capture.inject_synthetic_packet(
                src_ip=attacker_ip,
                dst_ip=target_ip,
                src_port=0,
                dst_port=0,
                protocol="ICMP",
                pkt_len=random.randint(64, 128)
            )
            time.sleep(0.015)

    def simulate_udp_flood(self, attacker_ip: str = "10.0.2.35", target_ip: str = "10.0.2.30", packet_count: int = 45):
        """Simulate UDP volumetric amplification flood (SIG-004)."""
        logger.info(f"Triggering UDP Flood from {attacker_ip} -> {target_ip}")
        for _ in range(packet_count):
            sport = random.randint(1024, 65535)
            self.packet_capture.inject_synthetic_packet(
                src_ip=attacker_ip,
                dst_ip=target_ip,
                src_port=sport,
                dst_port=random.choice([53, 123, 5000]),
                protocol="UDP",
                pkt_len=random.randint(1100, 1450)
            )
            time.sleep(0.015)

    def simulate_zero_day_anomaly(self, attacker_ip: str = "10.0.2.99", target_ip: str = "10.0.2.30", packet_count: int = 25):
        """
        Simulate an unknown, zero-day anomalous flow:
        - High entropy packet sizes
        - Unusual flag combinations (SYN+FIN+URG)
        - Non-standard port behaviors
        Does not match static signatures directly, but Isolation Forest immediately detects anomaly!
        """
        logger.info(f"Triggering Zero-Day ML Anomaly from {attacker_ip} -> {target_ip}")
        sport = random.randint(20000, 30000)
        dport = 8443
        for i in range(packet_count):
            self.packet_capture.inject_synthetic_packet(
                src_ip=attacker_ip,
                dst_ip=target_ip,
                src_port=sport,
                dst_port=dport,
                protocol="TCP",
                pkt_len=random.randint(700, 1400),
                tcp_flags={"S": True, "F": True, "U": True} # Abnormal TCP flag combo
            )
            time.sleep(0.02)
