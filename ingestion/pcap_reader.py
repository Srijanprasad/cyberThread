"""
Passive PCAP Ingestion Reader for Unidirectional Monitoring Enclave.
Reads live or captured network dumps without generating active network packets.
"""

import os
import time
from typing import Iterator, Optional
from scapy.all import rdpcap, PcapReader, IP, TCP, UDP, DNS, DNSQR, Raw

from ingestion.schema import PacketRecord, VisibilityMask


class PassivePCAPReader:
    """Passively parses PCAP streams assuming unidirectional data diode capture."""

    def __init__(self, is_reverse_observable: bool = False, data_quality_score: float = 0.85):
        self.visibility = VisibilityMask(
            is_reverse_observable=is_reverse_observable,
            data_quality_score=data_quality_score
        )

    def read_packets(self, pcap_path: str, max_packets: Optional[int] = None) -> Iterator[PacketRecord]:
        """Streams packets from PCAP file, yielding normalized PacketRecord objects."""
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        count = 0
        with PcapReader(pcap_path) as pcap_reader:
            for pkt in pcap_reader:
                if IP not in pkt:
                    continue

                ip_layer = pkt[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                proto = "OTHER"
                src_port = 0
                dst_port = 0
                flags = []
                dns_query = None
                dns_qtype = None
                http_method = None
                payload_str = None

                if TCP in pkt:
                    proto = "TCP"
                    tcp_layer = pkt[TCP]
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    # TCP Flags
                    f_int = int(tcp_layer.flags)
                    if f_int & 0x02:
                        flags.append("SYN")
                    if f_int & 0x10:
                        flags.append("ACK")
                    if f_int & 0x01:
                        flags.append("FIN")
                    if f_int & 0x04:
                        flags.append("RST")
                    if f_int & 0x08:
                        flags.append("PSH")
                    if f_int & 0x20:
                        flags.append("URG")

                    if Raw in pkt:
                        try:
                            raw_data = pkt[Raw].load
                            payload_str = raw_data.decode("utf-8", errors="ignore")[:300]
                            if payload_str.startswith(("GET ", "POST ", "HEAD ", "PUT ", "DELETE ")):
                                http_method = payload_str.split()[0]
                        except Exception:
                            pass

                elif UDP in pkt:
                    proto = "UDP"
                    udp_layer = pkt[UDP]
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport

                    if DNS in pkt and pkt[DNS].qd:
                        qd = pkt[DNS].qd
                        if isinstance(qd, DNSQR):
                            try:
                                dns_query = qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                                dns_qtype = str(qd.qtype)
                            except Exception:
                                pass
                    elif Raw in pkt:
                        payload_str = "UDP Payload"

                pkt_record = PacketRecord(
                    timestamp=float(pkt.time),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto,
                    length=len(pkt),
                    tcp_flags=flags,
                    dns_query=dns_query,
                    dns_qtype=dns_qtype,
                    http_method=http_method,
                    payload_preview=payload_str,
                    visibility=self.visibility,
                )

                yield pkt_record
                count += 1
                if max_packets and count >= max_packets:
                    break
