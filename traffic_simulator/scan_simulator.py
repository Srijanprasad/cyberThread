"""
Reconnaissance & Port Scan Traffic Simulator.
Generates both aggressive SYN scans and stealthy distributed slow scans.
"""

import random
import time
from typing import List
from ingestion.schema import PacketRecord


SCAN_TARGET_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 9200
]


class ScanTrafficGenerator:
    """Simulates port scans and reconnaissance."""

    def __init__(self, attacker_ip: str = "192.168.10.201", target_ip: str = "10.0.0.50"):
        self.attacker_ip = attacker_ip
        self.target_ip = target_ip

    def generate_rapid_syn_scan(self, base_timestamp: float, port_count: int = 30) -> List[PacketRecord]:
        """Aggressive SYN port scan targeting numerous destination ports rapidly."""
        packets = []
        t = base_timestamp
        selected_ports = random.sample(SCAN_TARGET_PORTS * 3, min(port_count, len(SCAN_TARGET_PORTS) * 3))

        for port in selected_ports:
            t += random.uniform(0.005, 0.02)  # fast burst
            src_port = random.randint(40000, 65000)
            pkt = PacketRecord(
                timestamp=t,
                src_ip=self.attacker_ip,
                dst_ip=self.target_ip,
                src_port=src_port,
                dst_port=port,
                protocol="TCP",
                length=random.choice([54, 60]),
                tcp_flags=["SYN"],
                payload_preview="TCP SYN probe",
            )
            packets.append(pkt)
        return packets

    def generate_slow_stealth_scan(self, base_timestamp: float, probe_count: int = 15) -> List[PacketRecord]:
        """
        Stealthy slow scan spaced out over medium/long temporal windows.
        Designed to stay under conventional short-term pps thresholds.
        """
        packets = []
        t = base_timestamp
        selected_ports = random.sample(SCAN_TARGET_PORTS, min(probe_count, len(SCAN_TARGET_PORTS)))

        for port in selected_ports:
            t += random.uniform(2.5, 6.0)  # Slow spacing
            src_port = random.randint(40000, 65000)
            pkt = PacketRecord(
                timestamp=t,
                src_ip=self.attacker_ip,
                dst_ip=self.target_ip,
                src_port=src_port,
                dst_port=port,
                protocol="TCP",
                length=60,
                tcp_flags=["SYN"],
                payload_preview="Stealth SYN probe",
            )
            packets.append(pkt)
        return packets
