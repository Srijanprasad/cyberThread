"""
Slowloris & Slow HTTP Request Exhaustion Simulator.
Emulates slow HTTP DoS attacks by holding connections open with intermittent header trickles.
Tailored for testing one-way visibility where server responses cannot be seen.
"""

import random
import time
from typing import List
from ingestion.schema import PacketRecord


class SlowlorisTrafficGenerator:
    """Generates Slowloris low-and-slow HTTP exhaustion packets."""

    def __init__(self, attacker_ip: str = "192.168.10.210", target_ip: str = "10.0.0.80"):
        self.attacker_ip = attacker_ip
        self.target_ip = target_ip

    def generate_slowloris_attack(
        self,
        base_timestamp: float,
        connections: int = 5,
        headers_per_conn: int = 6
    ) -> List[PacketRecord]:
        """
        Generates partial HTTP connections with slow-trickle header bursts.
        Does NOT send terminal \\r\\n\\r\\n.
        """
        packets = []
        t = base_timestamp

        for c_idx in range(connections):
            src_port = 45000 + c_idx
            conn_time = t + (c_idx * 0.1)

            # 1. Initial SYN
            packets.append(PacketRecord(
                timestamp=conn_time,
                src_ip=self.attacker_ip,
                dst_ip=self.target_ip,
                src_port=src_port,
                dst_port=80,
                protocol="TCP",
                length=60,
                tcp_flags=["SYN"],
                payload_preview="TCP SYN (Initial Slowloris socket)",
            ))

            # 2. Initial partial GET request
            conn_time += 0.05
            packets.append(PacketRecord(
                timestamp=conn_time,
                src_ip=self.attacker_ip,
                dst_ip=self.target_ip,
                src_port=src_port,
                dst_port=80,
                protocol="TCP",
                length=120,
                tcp_flags=["ACK", "PSH"],
                http_method="GET",
                http_uri="/",
                payload_preview="GET / HTTP/1.1\r\nHost: target.internal\r\nUser-Agent: Mozilla/5.0\r\n",
            ))

            # 3. Slow trickle of keep-alive headers every 4-8 seconds
            for h_idx in range(headers_per_conn):
                conn_time += random.uniform(4.0, 8.0)
                header_name = f"X-Header-{h_idx}"
                header_val = str(random.randint(1000, 9999))
                payload = f"{header_name}: {header_val}\r\n"

                packets.append(PacketRecord(
                    timestamp=conn_time,
                    src_ip=self.attacker_ip,
                    dst_ip=self.target_ip,
                    src_port=src_port,
                    dst_port=80,
                    protocol="TCP",
                    length=54 + len(payload),
                    tcp_flags=["ACK", "PSH"],
                    payload_preview=payload,
                ))

        # Sort all interleaved packets chronologically
        packets.sort(key=lambda p: p.timestamp)
        return packets
