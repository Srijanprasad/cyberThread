"""
SYN & UDP Flood Simulator (hping3 style).
Generates high-rate volumetric spikes, change-point bursts, and flag anomalies.
"""

import random
import time
from typing import List
from ingestion.schema import PacketRecord


class FloodTrafficGenerator:
    """Generates SYN and UDP flood attack streams."""

    def __init__(self, attacker_ip: str = "192.168.10.220", target_ip: str = "10.0.0.80"):
        self.attacker_ip = attacker_ip
        self.target_ip = target_ip

    def generate_syn_flood(self, base_timestamp: float, count: int = 120, spoof_sources: bool = False) -> List[PacketRecord]:
        """Simulates high-velocity SYN flood."""
        packets = []
        t = base_timestamp
        target_port = 80

        for _ in range(count):
            t += random.uniform(0.0005, 0.004)  # 250 - 2000 pps burst
            src = f"192.168.10.{random.randint(100, 250)}" if spoof_sources else self.attacker_ip
            src_port = random.randint(1024, 65535)

            pkt = PacketRecord(
                timestamp=t,
                src_ip=src,
                dst_ip=self.target_ip,
                src_port=src_port,
                dst_port=target_port,
                protocol="TCP",
                length=random.choice([54, 60]),
                tcp_flags=["SYN"],
                payload_preview="SYN flood packet",
            )
            packets.append(pkt)
        return packets

    def generate_udp_flood(self, base_timestamp: float, count: int = 120, target_port: int = 53) -> List[PacketRecord]:
        """Simulates volumetric UDP flood."""
        packets = []
        t = base_timestamp

        for _ in range(count):
            t += random.uniform(0.0005, 0.003)
            src_port = random.randint(1024, 65535)
            pkt = PacketRecord(
                timestamp=t,
                src_ip=self.attacker_ip,
                dst_ip=self.target_ip,
                src_port=src_port,
                dst_port=target_port,
                protocol="UDP",
                length=random.randint(512, 1400),
                payload_preview="UDP random amplification/payload flood",
            )
            packets.append(pkt)
        return packets
