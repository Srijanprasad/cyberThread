"""
Event Normalizer for SIH 2026 PS 26145.
Transforms heterogeneous packet, flow, and metadata streams
into canonical FlowEvent and DnsEvent objects.
Guarantees direction_seen = 'fwd'.
Never crashes on malformed data: counts and drops.
"""

from typing import Optional, Tuple, Any
from scapy.all import Packet, IP, TCP, UDP, DNS
from schemas.events import FlowEvent, DnsEvent


class EventNormalizer:
    def __init__(self):
        self.malformed_packets_dropped = 0
        self.total_packets_normalized = 0

    def normalize_packet(self, pkt: Packet) -> Tuple[Optional[FlowEvent], Optional[DnsEvent]]:
        """Normalizes a raw network packet into canonical events."""
        if IP not in pkt:
            self.malformed_packets_dropped += 1
            return None, None

        try:
            proto = pkt[IP].proto
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            ts = float(pkt.time)
            pkt_len = len(pkt)
            ttl = int(pkt[IP].ttl)

            sport = 0
            dport = 0
            flags_union = 0
            syn_c, ack_c, fin_c, rst_c = 0, 0, 0, 0

            if proto == 6 and TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                flags = int(pkt[TCP].flags)
                flags_union = flags
                syn_c = 1 if (flags & 0x02) else 0
                ack_c = 1 if (flags & 0x10) else 0
                fin_c = 1 if (flags & 0x01) else 0
                rst_c = 1 if (flags & 0x04) else 0
            elif proto == 17 and UDP in pkt:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
            else:
                self.malformed_packets_dropped += 1
                return None, None

            fe = FlowEvent(
                ts_start=ts,
                ts_end=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=sport,
                dst_port=dport,
                proto=proto,
                packets=1,
                bytes=pkt_len,
                tcp_flags_union=flags_union,
                syn_count=syn_c,
                ack_count=ack_c,
                fin_count=fin_c,
                rst_count=rst_c,
                min_ttl=ttl,
                max_ttl=ttl,
                mean_pkt_len=float(pkt_len),
                std_pkt_len=0.0,
                iat_mean=0.0,
                iat_std=0.0,
                direction_seen="fwd",
                source="pcap",
            )

            de: Optional[DnsEvent] = None
            if proto == 17 and UDP in pkt and DNS in pkt:
                dns = pkt[DNS]
                if dns.qr == 0 and dns.qd:  # Client query
                    qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                    qtype_code = dns.qd.qtype
                    qtype_map = {1: "A", 28: "AAAA", 16: "TXT", 5: "CNAME", 15: "MX", 12: "PTR"}
                    qtype_str = qtype_map.get(qtype_code, str(qtype_code))

                    de = DnsEvent(
                        ts=ts,
                        client_ip=src_ip,
                        resolver_ip=dst_ip,
                        qname=qname,
                        qtype=qtype_str,
                        qclass="IN",
                        edns_present=hasattr(dns, "ar") and dns.ar is not None,
                        payload_len=len(pkt[UDP].payload),
                    )

            self.total_packets_normalized += 1
            return fe, de

        except Exception:
            self.malformed_packets_dropped += 1
            return None, None
