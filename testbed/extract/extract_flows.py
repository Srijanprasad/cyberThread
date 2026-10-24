"""
Forward-Only Flow Extractor for SIH 2026 PS 26145.
Transforms raw unidirectional PCAP packets into canonical FlowEvents.
Enforces direction_seen = 'fwd'.
"""

import math
from typing import List, Dict, Any
from collections import defaultdict
from scapy.all import rdpcap, IP, TCP, UDP
from schemas.events import FlowEvent


def extract_flows_from_pcap(pcap_path: str, idle_timeout: float = 15.0) -> List[FlowEvent]:
    """Extracts canonical unidirectional FlowEvents from a PCAP file."""
    packets = rdpcap(pcap_path)
    # Key: (src_ip, dst_ip, src_port, dst_port, proto)
    flow_buckets = defaultdict(list)

    for pkt in packets:
        if IP not in pkt:
            continue
        proto = pkt[IP].proto
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        sport, dport = 0, 0
        if proto == 6 and TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif proto == 17 and UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        else:
            continue

        key = (src_ip, dst_ip, sport, dport, proto)
        flow_buckets[key].append(pkt)

    flow_events: List[FlowEvent] = []

    for (src_ip, dst_ip, sport, dport, proto), pkts in flow_buckets.items():
        # Sort packets by timestamp
        pkts.sort(key=lambda p: float(p.time))
        ts_start = float(pkts[0].time)
        ts_end = float(pkts[-1].time)

        pkt_count = len(pkts)
        byte_count = sum(len(p) for p in pkts)

        ttls = [int(p[IP].ttl) for p in pkts]
        min_ttl = min(ttls) if ttls else 64
        max_ttl = max(ttls) if ttls else 64

        pkt_lens = [float(len(p)) for p in pkts]
        mean_pkt_len = sum(pkt_lens) / pkt_count
        std_pkt_len = (
            math.sqrt(sum((x - mean_pkt_len) ** 2 for x in pkt_lens) / pkt_count)
            if pkt_count > 1
            else 0.0
        )

        iats = [float(pkts[i].time - pkts[i - 1].time) for i in range(1, pkt_count)]
        iat_mean = sum(iats) / len(iats) if iats else 0.0
        iat_std = (
            math.sqrt(sum((x - iat_mean) ** 2 for x in iats) / len(iats))
            if len(iats) > 1
            else 0.0
        )

        flags_union = 0
        syn_c, ack_c, fin_c, rst_c = 0, 0, 0, 0
        if proto == 6:
            for p in pkts:
                if TCP in p:
                    flags = int(p[TCP].flags)
                    flags_union |= flags
                    if flags & 0x02:
                        syn_c += 1
                    if flags & 0x10:
                        ack_c += 1
                    if flags & 0x01:
                        fin_c += 1
                    if flags & 0x04:
                        rst_c += 1

        fe = FlowEvent(
            ts_start=ts_start,
            ts_end=ts_end,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=sport,
            dst_port=dport,
            proto=proto,
            packets=pkt_count,
            bytes=byte_count,
            tcp_flags_union=flags_union,
            syn_count=syn_c,
            ack_count=ack_c,
            fin_count=fin_c,
            rst_count=rst_c,
            min_ttl=min_ttl,
            max_ttl=max_ttl,
            mean_pkt_len=mean_pkt_len,
            std_pkt_len=std_pkt_len,
            iat_mean=iat_mean,
            iat_std=iat_std,
            direction_seen="fwd",
            source="pcap",
        )
        flow_events.append(fe)

    return flow_events
