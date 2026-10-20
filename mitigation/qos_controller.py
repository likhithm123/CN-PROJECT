"""
Adaptive QoS Controller:
Manages QoS rate-limiting policies, enforces traffic tiers, and orchestrates
the dynamic feedback loop that relaxes restrictions once attack traffic subsides.
"""
import time
import platform
import logging
from typing import Dict, Any, List, Optional
from config.settings import QOS_COOLDOWN_SECONDS
from mitigation.drivers.virtual_qos import VirtualQoSEngine
from mitigation.drivers.linux_tc import LinuxTCDriver

logger = logging.getLogger("QoSController")

class QoSController:
    def __init__(self, cooldown_seconds: float = QOS_COOLDOWN_SECONDS):
        self.cooldown_seconds = cooldown_seconds
        self.system_os = platform.system().lower()
        self.virtual_engine = VirtualQoSEngine()

        self.linux_driver: Optional[LinuxTCDriver] = None
        if "linux" in self.system_os:
            self.linux_driver = LinuxTCDriver()
            self.linux_driver.initialize_root_qdisc()

        # Host last attack time for dynamic feedback loop
        self.last_attack_timestamp: Dict[str, float] = {}

    def apply_mitigation(self,
                         src_ip: str,
                         risk_score: float,
                         attack_type: str,
                         severity: str,
                         reason: str = "") -> Dict[str, Any]:
        """
        Evaluate risk score and apply appropriate QoS policy tier.
        """
        self.last_attack_timestamp[src_ip] = time.time()

        if severity == "CRITICAL" or risk_score >= 80.0:
            tier = "CRITICAL"
        elif severity == "HIGH" or risk_score >= 65.0:
            tier = "HIGH"
        elif severity == "SUSPICIOUS" or risk_score >= 35.0:
            tier = "SUSPICIOUS"
        else:
            tier = "NORMAL"

        full_reason = f"[{attack_type}] Risk: {risk_score:.1f}% - {reason}"
        policy = self.virtual_engine.set_policy(src_ip, tier, full_reason)

        # Apply to Linux tc if available
        if self.linux_driver and self.linux_driver.is_initialized:
            self.linux_driver.apply_ip_filter(src_ip, policy["class_id"])

        logger.info(f"Applied QoS Policy for {src_ip}: Tier={tier}, Rate={policy['rate_limit_mbps']} Mbps, Pri={policy['priority']}")
        return policy

    def process_feedback_loop(self) -> List[Dict[str, Any]]:
        """
        Feedback Loop: Periodically checks active throttled IPs.
        If no malicious activity is observed for cooldown_seconds,
        step down restrictions gradually (CRITICAL -> HIGH -> SUSPICIOUS -> NORMAL).
        """
        now = time.time()
        actions_taken = []
        active_policies = self.virtual_engine.get_all_active_policies()

        for ip, policy in list(active_policies.items()):
            current_tier = policy.get("tier", "NORMAL")
            if current_tier == "NORMAL":
                continue

            last_attack = self.last_attack_timestamp.get(ip, 0.0)
            elapsed = now - last_attack

            if elapsed >= self.cooldown_seconds:
                # Step-down transition
                if current_tier == "CRITICAL":
                    next_tier = "HIGH"
                elif current_tier == "HIGH":
                    next_tier = "SUSPICIOUS"
                elif current_tier == "SUSPICIOUS":
                    next_tier = "NORMAL"
                else:
                    next_tier = "NORMAL"

                msg = f"Traffic normalized for {elapsed:.1f}s. Stepping down restriction from {current_tier} to {next_tier}."
                if next_tier == "NORMAL":
                    self.virtual_engine.remove_policy(ip)
                    if self.linux_driver and self.linux_driver.is_initialized:
                        self.linux_driver.remove_ip_filter(ip)
                else:
                    self.virtual_engine.set_policy(ip, next_tier, msg)
                    if self.linux_driver and self.linux_driver.is_initialized:
                        class_id = self.virtual_engine.classes[next_tier]["class_id"]
                        self.linux_driver.apply_ip_filter(ip, class_id)

                # Reset timer so next step down requires another cooldown window
                self.last_attack_timestamp[ip] = now
                actions_taken.append({
                    "ip": ip,
                    "previous_tier": current_tier,
                    "new_tier": next_tier,
                    "message": msg
                })

        return actions_taken

    def get_active_mitigations(self) -> List[Dict[str, Any]]:
        """Return list of active rate-limited IPs and their details."""
        policies = self.virtual_engine.get_all_active_policies()
        return list(policies.values())

    def manual_override(self, ip: str, tier: str) -> Dict[str, Any]:
        """Allow administrator to manually set or release a QoS policy."""
        if tier == "NORMAL":
            self.virtual_engine.remove_policy(ip)
            if ip in self.last_attack_timestamp:
                del self.last_attack_timestamp[ip]
            return {"ip": ip, "tier": "NORMAL", "message": "Policy cleared"}
        return self.virtual_engine.set_policy(ip, tier, "Administrator manual override")
