"""
Unidirectional Flow Feature Aggregator.
Assembles passively captured egress packets into uniflows and extracts statistical signatures.
"""

import numpy as np
from typing import Dict, List, Any, Optional
from ingestion.schema import PacketRecord, FlowRecord, VisibilityMask
from features.dns_features import calculate_entropy


class FlowAggregator:
    """
    Maintains in-memory unidirectional flows, aggregating packet metrics
    over sliding micro-windows.
    """

    def __init__(self, flow_timeout_sec: float = 30.0):
        self.flow_timeout_sec = flow_timeout_sec
        self.active_flows: Dict[str, Dict[str, Any]] = {}

    def get_flow_key(self, pkt: PacketRecord) -> str:
        """Unidirectional flow key (src_ip:src_port -> dst_ip:dst_port:protocol)."""
        return f"{pkt.src_ip}:{pkt.src_port}->{pkt.dst_ip}:{pkt.dst_port}:{pkt.protocol}"

    def update(self, pkt: PacketRecord) -> FlowRecord:
        """
        Updates an existing flow or initializes a new unidirectional flow.
        Returns the updated FlowRecord.
        """
        key = self.get_flow_key(pkt)
        now = pkt.timestamp

        if key not in self.active_flows or (now - self.active_flows[key]["last_time"]) > self.flow_timeout_sec:
            # Initialize new flow
            self.active_flows[key] = {
                "flow_id": key,
                "src_ip": pkt.src_ip,
                "dst_ip": pkt.dst_ip,
                "src_port": pkt.src_port,
                "dst_port": pkt.dst_port,
                "protocol": pkt.protocol,
                "start_time": now,
                "last_time": now,
                "packet_count": 0,
                "byte_count": 0,
                "packet_sizes": [],
                "arrival_times": [],
                "syn_count": 0,
                "ack_count": 0,
                "fin_count": 0,
                "rst_count": 0,
                "psh_count": 0,
                "dns_queries": [],
                "dns_entropy_max": 0.0,
                "dns_label_len_max": 0,
                "dns_unique_subdomains": set(),
                "http_incomplete": False,
                "http_header_count": 0,
            }

        flow = self.active_flows[key]
        flow["last_time"] = now
        flow["packet_count"] += 1
        flow["byte_count"] += pkt.length
        flow["packet_sizes"].append(pkt.length)
        flow["arrival_times"].append(now)

        # Flag inspection
        flags = set(pkt.tcp_flags)
        if "SYN" in flags:
            flow["syn_count"] += 1
        if "ACK" in flags:
            flow["ack_count"] += 1
        if "FIN" in flags:
            flow["fin_count"] += 1
        if "RST" in flags:
            flow["rst_count"] += 1
        if "PSH" in flags:
            flow["psh_count"] += 1

        # DNS query tracking
        if pkt.dns_query:
            flow["dns_queries"].append(pkt.dns_query)
            clean_q = pkt.dns_query.strip(".")
            labels = clean_q.split(".")
            max_label = max((len(lbl) for lbl in labels), default=0)
            if max_label > flow["dns_label_len_max"]:
                flow["dns_label_len_max"] = max_label
            if len(labels) > 2:
                flow["dns_unique_subdomains"].add(".".join(labels[:-2]))
            
            # Compute query entropy
            ent = calculate_entropy(clean_q)
            if ent > flow["dns_entropy_max"]:
                flow["dns_entropy_max"] = ent

        # HTTP partial / slowloris inspection
        if pkt.http_method or (pkt.payload_preview and ("GET " in pkt.payload_preview or "POST " in pkt.payload_preview)):
            flow["http_header_count"] += 1
            if pkt.payload_preview and "\r\n\r\n" not in pkt.payload_preview:
                flow["http_incomplete"] = True
        elif pkt.payload_preview and "X-" in pkt.payload_preview and "\r\n\r\n" not in pkt.payload_preview:
            # Slowloris keep-alive trickle headers
            flow["http_header_count"] += 1
            flow["http_incomplete"] = True

        return self._to_flow_record(flow)

    def _to_flow_record(self, flow: Dict[str, Any]) -> FlowRecord:
        """Converts internal raw state to a standardized FlowRecord."""
        raw_dur = flow["last_time"] - flow["start_time"]
        duration = max(0.0, raw_dur)
        pkt_count = flow["packet_count"]
        byte_count = flow["byte_count"]

        # If flow duration is very small (< 0.1s), PPS is simply packet count, not an inflated division
        if duration >= 0.1:
            pps = pkt_count / duration
            bps = byte_count / duration
        else:
            pps = float(pkt_count)
            bps = float(byte_count)

        sizes = np.array(flow["packet_sizes"])
        mean_size = float(np.mean(sizes)) if len(sizes) > 0 else 0.0
        std_size = float(np.std(sizes)) if len(sizes) > 1 else 0.0

        times = np.array(flow["arrival_times"])
        if len(times) > 1:
            iats = np.diff(times)
            iat_mean = float(np.mean(iats))
            iat_std = float(np.std(iats))
        else:
            iat_mean = 0.0
            iat_std = 0.0

        return FlowRecord(
            flow_id=flow["flow_id"],
            src_ip=flow["src_ip"],
            dst_ip=flow["dst_ip"],
            src_port=flow["src_port"],
            dst_port=flow["dst_port"],
            protocol=flow["protocol"],
            start_time=flow["start_time"],
            last_time=flow["last_time"],
            duration=duration,
            packet_count=pkt_count,
            byte_count=byte_count,
            packets_per_sec=pps,
            bytes_per_sec=bps,
            mean_packet_size=mean_size,
            std_packet_size=std_size,
            iat_mean=iat_mean,
            iat_std=iat_std,
            syn_count=flow["syn_count"],
            ack_count=flow["ack_count"],
            fin_count=flow["fin_count"],
            rst_count=flow["rst_count"],
            psh_count=flow["psh_count"],
            dns_query_count=len(flow["dns_queries"]),
            dns_entropy_max=flow["dns_entropy_max"],
            dns_label_len_max=flow["dns_label_len_max"],
            dns_unique_subdomains=len(flow["dns_unique_subdomains"]),
            http_incomplete=flow["http_incomplete"],
            http_header_count=flow["http_header_count"],
            visibility=VisibilityMask(),
        )

    def cleanup_stale_flows(self, current_time: float) -> int:
        """Prunes expired flows to keep memory bounded."""
        stale_keys = [
            k for k, v in self.active_flows.items()
            if (current_time - v["last_time"]) > self.flow_timeout_sec
        ]
        for k in stale_keys:
            del self.active_flows[k]
        return len(stale_keys)
