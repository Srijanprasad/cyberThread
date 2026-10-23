"""
Synthetic Benign Traffic Generator.
Generates normal corporate/lab network traffic: Web (HTTP/HTTPS), DNS queries,
NTP syncs, and typical user inter-arrival patterns.
"""

import random
import time
from typing import List
from ingestion.schema import PacketRecord


COMMON_DOMAINS = [
    "google.com", "microsoft.com", "github.com", "cloudflare.com",
    "ntro.gov.in", "nic.in", "aws.amazon.com", "wikipedia.org",
    "ubuntu.com", "python.org", "api.github.com", "cdn.jsdelivr.net"
]

BENIGN_CLIENTS = [
    "192.168.10.15", "192.168.10.22", "192.168.10.45",
    "192.168.10.88", "192.168.10.104"
]

BENIGN_SERVERS = [
    ("142.250.190.46", 443, "HTTPS"),
    ("104.244.42.1", 443, "HTTPS"),
    ("185.199.108.153", 80, "HTTP"),
    ("8.8.8.8", 53, "DNS"),
    ("1.1.1.1", 53, "DNS"),
    ("216.239.35.0", 123, "NTP"),
]


class BenignTrafficGenerator:
    """Generates synthetic normal background traffic."""

    def __init__(self, base_timestamp: float = None):
        self.current_time = base_timestamp or time.time()

    def generate_packets(self, count: int = 50) -> List[PacketRecord]:
        packets = []
        for _ in range(count):
            self.current_time += random.uniform(0.01, 0.25)
            src_ip = random.choice(BENIGN_CLIENTS)
            dst_ip, dst_port, service = random.choice(BENIGN_SERVERS)
            src_port = random.randint(32768, 61000)

            if service == "DNS":
                domain = random.choice(COMMON_DOMAINS)
                pkt = PacketRecord(
                    timestamp=self.current_time,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=53,
                    protocol="UDP",
                    length=random.randint(60, 95),
                    dns_query=domain,
                    dns_qtype="A",
                )
            elif service == "HTTP":
                pkt = PacketRecord(
                    timestamp=self.current_time,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=80,
                    protocol="TCP",
                    length=random.randint(250, 650),
                    tcp_flags=["ACK", "PSH"],
                    http_method="GET",
                    http_uri="/index.html",
                    payload_preview=f"GET /index.html HTTP/1.1\r\nHost: {dst_ip}\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
                )
            elif service == "HTTPS":
                # TLS Client Hello / Application Data
                pkt = PacketRecord(
                    timestamp=self.current_time,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=443,
                    protocol="TCP",
                    length=random.randint(500, 1420),
                    tcp_flags=["ACK", "PSH"],
                    payload_preview="TLSv1.3 Application Data",
                )
            else:
                pkt = PacketRecord(
                    timestamp=self.current_time,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol="UDP",
                    length=random.randint(48, 72),
                )
            packets.append(pkt)
        return packets
