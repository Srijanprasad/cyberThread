"""
DNS Tunneling & DGA Simulator (iodine / dnscat2 style).
Generates high-entropy encoded queries, long subdomain payloads, and DGA queries.
"""

import random
import string
import time
from typing import List
from ingestion.schema import PacketRecord


class DNSAnomalyTrafficGenerator:
    """Simulates DNS data exfiltration, tunneling, and DGA lookups."""

    def __init__(self, attacker_ip: str = "192.168.10.180", dns_server: str = "8.8.8.8"):
        self.attacker_ip = attacker_ip
        self.dns_server = dns_server
        self.tunnel_domain = "exfil-tunnel.darkcorp.net"

    def _generate_encoded_payload(self, length: int = 48) -> str:
        """Generates high-entropy base32/hex data chunk simulating iodine/dnscat2."""
        chars = string.ascii_lowercase + string.digits
        return "".join(random.choice(chars) for _ in range(length))

    def _generate_dga_domain(self) -> str:
        """Generates pseudo-random algorithmic domain."""
        length = random.randint(12, 22)
        vowels = "aeiou"
        consonants = "bcdfghjklmnpqrstvwxyz"
        chars = consonants * 3 + vowels
        name = "".join(random.choice(chars) for _ in range(length))
        tld = random.choice(["biz", "info", "top", "xyz", "cc"])
        return f"{name}.{tld}"

    def generate_dns_tunneling(
        self,
        base_timestamp: float,
        query_count: int = 35
    ) -> List[PacketRecord]:
        """
        Simulates an active DNS tunneling session exfiltrating encoded files.
        Characterized by long subdomains, high entropy, and bursty frequency.
        """
        packets = []
        t = base_timestamp

        for _ in range(query_count):
            t += random.uniform(0.08, 0.35)  # rapid query stream
            src_port = random.randint(35000, 62000)
            chunk1 = self._generate_encoded_payload(random.randint(40, 52))
            chunk2 = self._generate_encoded_payload(random.randint(15, 25))
            full_query = f"{chunk1}.{chunk2}.{self.tunnel_domain}"
            qtype = random.choice(["TXT", "CNAME", "NULL", "A"])

            pkt = PacketRecord(
                timestamp=t,
                src_ip=self.attacker_ip,
                dst_ip=self.dns_server,
                src_port=src_port,
                dst_port=53,
                protocol="UDP",
                length=random.randint(120, 220),
                dns_query=full_query,
                dns_qtype=qtype,
                payload_preview=f"DNS Q {qtype} {full_query}",
            )
            packets.append(pkt)

        return packets

    def generate_dga_burst(
        self,
        base_timestamp: float,
        query_count: int = 20
    ) -> List[PacketRecord]:
        """Simulates infected host cycling through DGA domains attempting C2 resolution."""
        packets = []
        t = base_timestamp

        for _ in range(query_count):
            t += random.uniform(0.2, 0.8)
            src_port = random.randint(35000, 62000)
            dga_domain = self._generate_dga_domain()

            pkt = PacketRecord(
                timestamp=t,
                src_ip=self.attacker_ip,
                dst_ip=self.dns_server,
                src_port=src_port,
                dst_port=53,
                protocol="UDP",
                length=random.randint(70, 110),
                dns_query=dga_domain,
                dns_qtype="A",
                payload_preview=f"DNS Q A {dga_domain} (DGA)",
            )
            packets.append(pkt)

        return packets
