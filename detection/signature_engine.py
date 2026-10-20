"""
Signature Engine: Implements rule-based intrusion detection against known attack patterns
such as Port Scans, SYN Floods, ICMP Floods, UDP Floods, and Sensitive Service Probing.
"""
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional
from config.settings import RULES_CONFIG_PATH

class SignatureEngine:
    def __init__(self, config_path: Path = RULES_CONFIG_PATH):
        self.config_path = config_path
        self.rules = []
        self.load_rules()

    def load_rules(self):
        """Load signature rules from YAML configuration."""
        if not self.config_path.exists():
            self.rules = []
            return
        with open(self.config_path, "r") as f:
            data = yaml.safe_load(f)
            self.rules = data.get("rules", [])

    def evaluate(self, flow: Dict[str, Any], features: Dict[str, float], src_stats: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Evaluate an active flow and its features against all registered signature rules.
        Returns the highest-scoring signature match, or benign if no rules trigger.
        """
        best_match = {
            "detected": False,
            "rule_id": None,
            "attack": "Normal",
            "severity": "LOW",
            "score": 0.0,
            "details": "No signature matched"
        }

        proto = flow.get("protocol", "")
        dst_port = int(flow.get("dst_port", 0))
        packets = flow.get("packets", 0)
        pps = features.get("packets_per_sec", 0.0)
        bps = features.get("bytes_per_sec", 0.0)
        syn_count = flow.get("syn_count", 0)
        ack_count = flow.get("ack_count", 0)
        syn_ack_ratio = features.get("syn_ack_ratio", 0.0)
        unique_ports = features.get("unique_dst_ports", 1.0)
        duration = features.get("flow_duration", 0.001)

        for rule in self.rules:
            rule_id = rule.get("id")
            cond = rule.get("conditions", {})
            rule_proto = rule.get("protocol")

            # Check Protocol match if specified
            if rule_proto and rule_proto != proto:
                continue

            matched = False
            detail_str = ""

            # SIG-001: Port Scan
            if rule_id == "SIG-001":
                min_unique = cond.get("unique_dst_ports_min", 8)
                if unique_ports >= min_unique and (syn_count >= min_unique or pps >= 10.0):
                    matched = True
                    detail_str = f"Contacted {int(unique_ports)} distinct ports (threshold: {min_unique})"

            # SIG-002: SYN Flood
            elif rule_id == "SIG-002":
                min_syn = cond.get("syn_count_min", 30)
                min_ratio = cond.get("syn_ack_ratio_min", 4.0)
                min_pps = cond.get("packets_per_sec_min", 25.0)

                host_syn = src_stats.get("syn_count", 0) if src_stats else 0
                host_ack = src_stats.get("ack_count", 0) if src_stats else 0
                host_ratio = float(host_syn) if host_ack == 0 else float(host_syn) / float(max(1, host_ack))

                if (syn_count >= min_syn and syn_ack_ratio >= min_ratio) or (host_syn >= min_syn and host_ratio >= min_ratio):
                    matched = True
                    eff_syn = max(syn_count, host_syn)
                    eff_ratio = max(syn_ack_ratio, host_ratio)
                    detail_str = f"High SYN flood volume ({eff_syn} SYNs) with SYN/ACK ratio {eff_ratio:.1f}"

            # SIG-003: ICMP Flood
            elif rule_id == "SIG-003":
                min_pps = cond.get("icmp_packets_per_sec_min", 30.0)
                min_pkts = cond.get("packet_count_min", 25)
                if proto == "ICMP" and packets >= min_pkts and pps >= min_pps:
                    matched = True
                    detail_str = f"ICMP flood burst: {packets} packets at {pps:.1f} PPS"

            # SIG-004: UDP Flood
            elif rule_id == "SIG-004":
                min_pps = cond.get("udp_packets_per_sec_min", 40.0)
                min_bps = cond.get("bytes_per_sec_min", 50000.0)
                if proto == "UDP" and pps >= min_pps and bps >= min_bps:
                    matched = True
                    detail_str = f"UDP volumetric flood: {pps:.1f} PPS, {bps/1024:.1f} KB/s"

            # SIG-005: Sensitive Port Probing
            elif rule_id == "SIG-005":
                target_ports = cond.get("target_ports", [])
                min_attempts = cond.get("connection_attempts_min", 3)
                if dst_port in target_ports and packets >= min_attempts:
                    matched = True
                    detail_str = f"Targeted sensitive service port {dst_port} ({packets} attempts)"

            # SIG-006: Brute Force
            elif rule_id == "SIG-006":
                target_ports = cond.get("target_ports", [])
                min_pps = cond.get("packets_per_sec_min", 35.0)
                if dst_port in target_ports and pps >= min_pps:
                    matched = True
                    detail_str = f"Rapid repeated connection burst to port {dst_port} ({pps:.1f} PPS)"

            # SIG-007: DNS Tunneling & Covert Exfiltration
            elif rule_id == "SIG-007":
                dns_entropy = float(features.get("dns_entropy", 0.0) or flow.get("dns_entropy", 0.0))
                dns_len = float(features.get("dns_length", 0.0) or flow.get("dns_length", 0.0))
                min_entropy = cond.get("dns_entropy_min", 3.5)
                min_len = cond.get("dns_length_min", 32)
                if (dst_port == 53 or flow.get("dst_port") == 53) and (dns_entropy >= min_entropy or dns_len >= min_len):
                    matched = True
                    detail_str = f"DNS Tunneling detected: query length {int(dns_len)}, entropy {dns_entropy:.2f} (threshold: {min_entropy})"


            if matched:
                score = float(rule.get("score", 70.0))
                if score > best_match["score"]:
                    best_match = {
                        "detected": True,
                        "rule_id": rule_id,
                        "attack": rule.get("name"),
                        "severity": rule.get("severity", "MEDIUM"),
                        "score": score,
                        "details": detail_str
                    }

        return best_match
