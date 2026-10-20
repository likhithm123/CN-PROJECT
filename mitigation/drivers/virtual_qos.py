"""
Virtual QoS Engine: Cross-platform software emulation of traffic control (tc)
and hierarchical token bucket (HTB) rate limiting.
Enables local testing and demonstration on macOS and environments without root.
"""
import time
from typing import Dict, Any, Optional

class VirtualQoSEngine:
    def __init__(self):
        # Maps IP -> QoS Profile
        self.ip_profiles: Dict[str, Dict[str, Any]] = {}
        # Global classes definition
        self.classes = {
            "NORMAL": {"class_id": "1:10", "rate_limit_mbps": 100.0, "priority": 1, "description": "Unrestricted Full Speed"},
            "SUSPICIOUS": {"class_id": "1:20", "rate_limit_mbps": 10.0, "priority": 2, "description": "Monitored Soft Throttling"},
            "HIGH": {"class_id": "1:30", "rate_limit_mbps": 2.0, "priority": 3, "description": "Strict Bandwidth Throttling"},
            "CRITICAL": {"class_id": "1:40", "rate_limit_mbps": 0.25, "priority": 4, "description": "Aggressive Isolation (256 Kbps)"}
        }

    def set_policy(self, ip: str, tier: str, reason: str = "") -> Dict[str, Any]:
        """Apply a QoS rate-limiting policy to an IP address."""
        if tier not in self.classes:
            tier = "NORMAL"

        class_info = self.classes[tier]
        profile = {
            "ip": ip,
            "tier": tier,
            "class_id": class_info["class_id"],
            "rate_limit_mbps": class_info["rate_limit_mbps"],
            "priority": class_info["priority"],
            "description": class_info["description"],
            "applied_at": time.time(),
            "last_updated": time.time(),
            "reason": reason,
            "packets_throttled": 0,
            "bytes_dropped": 0
        }
        self.ip_profiles[ip] = profile
        return profile

    def get_policy(self, ip: str) -> Dict[str, Any]:
        """Retrieve active policy for an IP, defaulting to NORMAL if unrestricted."""
        if ip in self.ip_profiles:
            return self.ip_profiles[ip]
        norm = self.classes["NORMAL"]
        return {
            "ip": ip,
            "tier": "NORMAL",
            "class_id": norm["class_id"],
            "rate_limit_mbps": norm["rate_limit_mbps"],
            "priority": norm["priority"],
            "description": norm["description"],
            "applied_at": 0.0,
            "last_updated": 0.0,
            "reason": "Default Normal Traffic",
            "packets_throttled": 0,
            "bytes_dropped": 0
        }

    def remove_policy(self, ip: str):
        """Restore IP to standard normal traffic status."""
        if ip in self.ip_profiles:
            del self.ip_profiles[ip]

    def get_all_active_policies(self) -> Dict[str, Dict[str, Any]]:
        return dict(self.ip_profiles)
