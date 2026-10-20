"""
Linux Traffic Control (tc / HTB) Driver:
Interfaces with Linux kernel `tc` and `iptables` to configure real bandwidth
classes, rate limits, and packet queueing disciplines.
"""
import subprocess
import logging

logger = logging.getLogger("LinuxTCDriver")

class LinuxTCDriver:
    def __init__(self, interface: str = "eth0"):
        self.interface = interface
        self.is_initialized = False

    def initialize_root_qdisc(self):
        """Setup root HTB queueing discipline on the Linux network interface."""
        try:
            # Clear any existing qdisc
            subprocess.run(
                ["tc", "qdisc", "del", "dev", self.interface, "root"],
                capture_output=True, text=True
            )
            # Add root HTB qdisc
            subprocess.run(
                ["tc", "qdisc", "add", "dev", self.interface, "root", "handle", "1:", "htb", "default", "10"],
                check=True, capture_output=True, text=True
            )
            # Class 1:10 - Default / Normal Traffic (100 Mbps, Pri 1)
            subprocess.run(
                ["tc", "class", "add", "dev", self.interface, "parent", "1:", "classid", "1:10", "htb", "rate", "100mbit", "prio", "1"],
                check=True, capture_output=True, text=True
            )
            # Class 1:20 - Suspicious Traffic (10 Mbps, Pri 2)
            subprocess.run(
                ["tc", "class", "add", "dev", self.interface, "parent", "1:", "classid", "1:20", "htb", "rate", "10mbit", "prio", "2"],
                check=True, capture_output=True, text=True
            )
            # Class 1:30 - High Risk Traffic (2 Mbps, Pri 3)
            subprocess.run(
                ["tc", "class", "add", "dev", self.interface, "parent", "1:", "classid", "1:30", "htb", "rate", "2mbit", "prio", "3"],
                check=True, capture_output=True, text=True
            )
            # Class 1:40 - Critical Rate-Limited Traffic (256 Kbps, Pri 4)
            subprocess.run(
                ["tc", "class", "add", "dev", self.interface, "parent", "1:", "classid", "1:40", "htb", "rate", "256kbit", "prio", "4"],
                check=True, capture_output=True, text=True
            )
            self.is_initialized = True
            logger.info("Linux tc HTB qdisc classes initialized successfully.")
        except Exception as e:
            logger.warning(f"Unable to initialize Linux tc qdisc (may require root / Linux OS): {e}")
            self.is_initialized = False

    def apply_ip_filter(self, ip: str, class_id: str):
        """Direct traffic from specific source IP into target tc class."""
        if not self.is_initialized:
            return False
        try:
            # Map ip filter
            cmd = [
                "tc", "filter", "add", "dev", self.interface, "protocol", "ip",
                "parent", "1:0", "prio", "1", "u32", "match", "ip", "src", ip,
                "flowid", class_id
            ]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            return True
        except Exception as e:
            logger.error(f"Error applying tc filter for IP {ip}: {e}")
            return False

    def remove_ip_filter(self, ip: str):
        """Remove tc filter for specific IP."""
        pass
