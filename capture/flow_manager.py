"""
Flow Manager: Aggregates incoming packets into 5-tuple bidirectional/unidirectional
network flows and tracks per-host metrics.
"""
import time
from typing import Dict, Tuple, Any, List, Optional
from collections import defaultdict

class FlowManager:
    def __init__(self, timeout_seconds: float = 10.0):
        self.timeout_seconds = timeout_seconds
        # flows key: (src_ip, dst_ip, src_port, dst_port, protocol)
        self.flows: Dict[Tuple[str, str, int, int, str], Dict[str, Any]] = {}
        # Per-source IP tracking for port scan detection
        self.src_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "dst_ports": set(),
            "last_seen": time.time(),
            "packet_count": 0,
            "byte_count": 0,
            "syn_count": 0,
            "ack_count": 0
        })
        self.total_packets_processed = 0
        self.total_bytes_processed = 0

    def add_packet(self,
                   src_ip: str,
                   dst_ip: str,
                   src_port: int,
                   dst_port: int,
                   protocol: str,
                   pkt_len: int,
                   tcp_flags: Optional[Dict[str, bool]] = None,
                   timestamp: Optional[float] = None,
                   dns_entropy: Optional[float] = None,
                   dns_length: Optional[float] = None) -> Tuple[Tuple[str, str, int, int, str], Dict[str, Any]]:
        """
        Process a single packet and update corresponding flow and source host metrics.
        """
        ts = timestamp if timestamp is not None else time.time()
        self.total_packets_processed += 1
        self.total_bytes_processed += pkt_len

        # Canonical bidirectional flow key
        if (src_ip, src_port) <= (dst_ip, dst_port):
            flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
            fwd = True
        else:
            flow_key = (dst_ip, src_ip, dst_port, src_port, protocol)
            fwd = False

        if flow_key not in self.flows:
            self.flows[flow_key] = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "start_time": ts,
                "last_seen": ts,
                "duration": 0.001,
                "packets": 0,
                "bytes": 0,
                "syn_count": 0,
                "ack_count": 0,
                "fin_count": 0,
                "rst_count": 0,
                "psh_count": 0,
                "urg_count": 0,
                "dns_entropy": 0.0,
                "dns_length": 0.0
            }

        flow = self.flows[flow_key]
        flow["packets"] += 1
        flow["bytes"] += pkt_len
        flow["last_seen"] = ts
        flow["duration"] = max(0.001, ts - flow["start_time"])
        if dns_entropy is not None and dns_entropy > flow["dns_entropy"]:
            flow["dns_entropy"] = dns_entropy
        if dns_length is not None and dns_length > flow["dns_length"]:
            flow["dns_length"] = dns_length


        src_entry = self.src_stats[src_ip]
        if tcp_flags:
            if tcp_flags.get("S"):
                flow["syn_count"] += 1
                src_entry["syn_count"] += 1
            if tcp_flags.get("A"):
                flow["ack_count"] += 1
                src_entry["ack_count"] += 1
            if tcp_flags.get("F"): flow["fin_count"] += 1
            if tcp_flags.get("R"): flow["rst_count"] += 1
            if tcp_flags.get("P"): flow["psh_count"] += 1
            if tcp_flags.get("U"): flow["urg_count"] += 1

        # Update host-level tracking
        src_entry["dst_ports"].add(dst_port)
        src_entry["last_seen"] = ts
        src_entry["packet_count"] += 1
        src_entry["byte_count"] += pkt_len

        return flow_key, flow

    def get_active_flows(self) -> List[Dict[str, Any]]:
        """Return list of active flows with accurate packet-trace duration."""
        active = []
        for key, flow in list(self.flows.items()):
            flow_copy = dict(flow)
            flow_copy["duration"] = max(0.001, flow["last_seen"] - flow["start_time"])
            active.append(flow_copy)
        return active

    def cleanup_expired_flows(self) -> int:
        """Remove flows that have not seen packets within timeout_seconds."""
        now = time.time()
        expired_keys = [
            k for k, v in self.flows.items()
            if (now - v["last_seen"]) > self.timeout_seconds
        ]
        for k in expired_keys:
            del self.flows[k]

        # Expire old host statistics if inactive for 30s
        for src_ip in list(self.src_stats.keys()):
            if (now - self.src_stats[src_ip]["last_seen"]) > 30.0:
                del self.src_stats[src_ip]

        return len(expired_keys)

    def reset_host_ports(self, src_ip: str):
        """Reset destination port set for a source IP periodically."""
        if src_ip in self.src_stats:
            self.src_stats[src_ip]["dst_ports"].clear()
