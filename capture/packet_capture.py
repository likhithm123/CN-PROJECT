"""
Packet Capture Engine: Interacts with Scapy to sniff live network traffic on an interface
or receive programmatically generated packets.
"""
import logging
import threading
import time
from typing import Callable, Optional
from scapy.all import sniff, IP, TCP, UDP, ICMP, AsyncSniffer
from capture.flow_manager import FlowManager

logger = logging.getLogger("PacketCapture")

class PacketCapture:
    def __init__(self,
                 flow_manager: FlowManager,
                 interface: Optional[str] = None,
                 on_packet_callback: Optional[Callable] = None):
        self.flow_manager = flow_manager
        self.interface = interface
        self.on_packet_callback = on_packet_callback
        self.is_running = False
        self._sniffer = None
        self._thread: Optional[threading.Thread] = None

    def _parse_packet(self, packet):
        """Extract network layer and transport layer info from Scapy packet."""
        try:
            if not packet.haslayer(IP):
                return

            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            pkt_len = len(packet)
            ts = float(packet.time) if hasattr(packet, "time") else time.time()

            src_port = 0
            dst_port = 0
            protocol = "OTHER"
            tcp_flags = None

            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                protocol = "TCP"
                flags = tcp_layer.flags
                tcp_flags = {
                    "S": bool(flags & 0x02), # SYN
                    "A": bool(flags & 0x10), # ACK
                    "F": bool(flags & 0x01), # FIN
                    "R": bool(flags & 0x04), # RST
                    "P": bool(flags & 0x08), # PSH
                    "U": bool(flags & 0x20)  # URG
                }
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                protocol = "UDP"
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
                src_port = 0
                dst_port = 0

            # DNS Query & Tunneling Feature Extraction
            dns_entropy = 0.0
            dns_length = 0.0
            if packet.haslayer("DNS"):
                try:
                    dns_layer = packet.getlayer("DNS")
                    if dns_layer and hasattr(dns_layer, "qd") and dns_layer.qd:
                        from features.extractor import FeatureExtractor
                        qname = dns_layer.qd.qname
                        if isinstance(qname, bytes):
                            qname_str = qname.decode("utf-8", errors="ignore").rstrip(".")
                        else:
                            qname_str = str(qname).rstrip(".")
                        dns_length = float(len(qname_str))
                        dns_entropy = FeatureExtractor.calculate_shannon_entropy(qname_str)
                except Exception:
                    pass

            flow_key, flow = self.flow_manager.add_packet(
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

            if self.on_packet_callback:
                self.on_packet_callback({
                    "timestamp": ts,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "length": pkt_len
                })

        except Exception as e:
            logger.debug(f"Packet parsing exception: {e}")

    def inject_synthetic_packet(self,
                                src_ip: str,
                                dst_ip: str,
                                src_port: int,
                                dst_port: int,
                                protocol: str,
                                pkt_len: int,
                                tcp_flags: Optional[dict] = None):
        """Inject packet directly without raw sockets (ideal for testing/simulations)."""
        ts = time.time()
        flow_key, flow = self.flow_manager.add_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            pkt_len=pkt_len,
            tcp_flags=tcp_flags,
            timestamp=ts
        )
        if self.on_packet_callback:
            self.on_packet_callback({
                "timestamp": ts,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "length": pkt_len
            })

    def start_live_capture(self):
        """Start Scapy live packet capture in background thread."""
        if self.is_running:
            return

        self.is_running = True

        def run_sniff():
            logger.info(f"Starting Scapy sniffing on interface: {self.interface or 'default'}")
            try:
                sniff_kwargs = {
                    "prn": self._parse_packet,
                    "store": False
                }
                if self.interface and self.interface != "auto":
                    sniff_kwargs["iface"] = self.interface

                sniff(**sniff_kwargs)
            except Exception as e:
                logger.error(f"Live sniffing stopped or permission denied: {e}")
                self.is_running = False

        self._thread = threading.Thread(target=run_sniff, daemon=True)
        self._thread.start()

    def stop_live_capture(self):
        self.is_running = False
