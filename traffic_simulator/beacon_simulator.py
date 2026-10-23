"""
Command & Control (C2) Beacon Simulator.
Emulates modern C2 frameworks (Cobalt Strike, Sliver, Mythic) exhibiting
regular or jittered outbound check-ins over HTTP/HTTPS.
"""

import random
import time
from typing import List
from ingestion.schema import PacketRecord


class BeaconTrafficGenerator:
    """Generates periodic C2 beaconing check-in flows."""

    def __init__(
        self,
        infected_ip: str = "192.168.10.155",
        c2_server: str = "198.51.100.77",
        interval_sec: float = 8.0,
        jitter_pct: float = 0.15  # 15% jitter
    ):
        self.infected_ip = infected_ip
        self.c2_server = c2_server
        self.interval = interval_sec
        self.jitter = jitter_pct

    def generate_beacons(
        self,
        base_timestamp: float,
        beacon_count: int = 10
    ) -> List[PacketRecord]:
        """
        Generates a sequence of periodic beacon check-ins with realistic jitter.
        """
        packets = []
        t = base_timestamp

        for beacon_idx in range(beacon_count):
            # Apply jitter to interval
            jitter_offset = random.uniform(-self.jitter * self.interval, self.jitter * self.interval)
            t += max(0.5, self.interval + jitter_offset)

            src_port = random.randint(49152, 65535)

            # 1. TCP SYN
            packets.append(PacketRecord(
                timestamp=t,
                src_ip=self.infected_ip,
                dst_ip=self.c2_server,
                src_port=src_port,
                dst_port=443,
                protocol="TCP",
                length=60,
                tcp_flags=["SYN"],
                payload_preview="TCP SYN (C2 Beacon handshake)",
            ))

            # 2. TLS Client Hello / Check-in POST
            t += 0.02
            packets.append(PacketRecord(
                timestamp=t,
                src_ip=self.infected_ip,
                dst_ip=self.c2_server,
                src_port=src_port,
                dst_port=443,
                protocol="TCP",
                length=random.choice([420, 428, 432]),  # repeated uniform size
                tcp_flags=["ACK", "PSH"],
                payload_preview=f"TLS Application Data (Beacon #{beacon_idx+1})",
            ))

        packets.sort(key=lambda p: p.timestamp)
        return packets
