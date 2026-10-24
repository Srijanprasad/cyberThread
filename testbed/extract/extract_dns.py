"""
Forward-Only DNS Query Extractor for SIH 2026 PS 26145.
Extracts canonical DnsEvents from client query packets.
Never requires or reads DNS server responses.
"""

from typing import List
from scapy.all import rdpcap, IP, UDP, DNS, DNSQR
from schemas.events import DnsEvent


def extract_dns_from_pcap(pcap_path: str) -> List[DnsEvent]:
    """Extracts query-only DnsEvents from PCAP."""
    packets = rdpcap(pcap_path)
    dns_events: List[DnsEvent] = []

    for pkt in packets:
        if IP in pkt and UDP in pkt and DNS in pkt:
            dns_layer = pkt[DNS]
            # qr == 0 means Query (forward from client)
            if dns_layer.qr == 0 and dns_layer.qd:
                qname = dns_layer.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                qtype_code = dns_layer.qd.qtype
                qtype_map = {1: "A", 28: "AAAA", 16: "TXT", 5: "CNAME", 15: "MX", 12: "PTR"}
                qtype_str = qtype_map.get(qtype_code, str(qtype_code))

                de = DnsEvent(
                    ts=float(pkt.time),
                    client_ip=pkt[IP].src,
                    resolver_ip=pkt[IP].dst,
                    qname=qname,
                    qtype=qtype_str,
                    qclass="IN",
                    edns_present=hasattr(dns_layer, "ar") and dns_layer.ar is not None,
                    payload_len=len(pkt[UDP].payload),
                )
                dns_events.append(de)

    return dns_events
