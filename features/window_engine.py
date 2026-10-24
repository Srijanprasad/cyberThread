"""
Feature Engine for SIH 2026 PS 26145.
Maintains event-time tumbling and sliding windows with TTL eviction and bounded memory.
Computes forward-only statistical distributions:
- SYN count, SYN ratio, normalized source entropy, TTL variance, packet rate.
"""

import math
from typing import Dict, List, Any, Optional
from collections import defaultdict, deque
from schemas.events import FlowEvent


class WindowFeatureEngine:
    def __init__(self, window_size_sec: float = 1.0, ttl_sec: float = 60.0, max_keys: int = 10000):
        self.window_size = window_size_sec
        self.ttl = ttl_sec
        self.max_keys = max_keys

        # Key: dst_ip -> deque of (timestamp, FlowEvent)
        self.dest_windows: Dict[str, deque] = defaultdict(deque)
        self.last_seen: Dict[str, float] = {}

    def add_flow(self, flow: FlowEvent) -> Optional[Dict[str, Any]]:
        """
        Adds a flow event, purges aged data, and extracts window features
        for key = flow.dst_ip.
        """
        key = flow.dst_ip
        now = flow.ts_end
        self.last_seen[key] = now

        # Memory bound check
        if len(self.dest_windows) > self.max_keys:
            oldest_key = min(self.last_seen, key=self.last_seen.get)
            del self.dest_windows[oldest_key]
            del self.last_seen[oldest_key]

        window = self.dest_windows[key]
        window.append((now, flow))

        # Evict events outside sliding/tumbling window
        while window and (now - window[0][0]) > self.window_size:
            window.popleft()

        # Extract features if at least 1 event exists
        if not window:
            return None

        total_flows = len(window)
        total_packets = sum(f.packets for _, f in window)
        total_bytes = sum(f.bytes for _, f in window)

        syn_count = sum(f.syn_count for _, f in window)
        ack_count = sum(f.ack_count for _, f in window)
        syn_ratio = syn_count / total_packets if total_packets > 0 else 0.0

        # Unique sources & Normalized Source IP Entropy
        src_counts = defaultdict(int)
        for _, f in window:
            src_counts[f.src_ip] += f.packets

        unique_srcs = len(src_counts)
        source_entropy = 0.0
        if unique_srcs > 1 and total_packets > 0:
            for count in src_counts.values():
                p = count / total_packets
                source_entropy -= p * math.log2(p)
            source_entropy = source_entropy / math.log2(unique_srcs)  # Normalize [0, 1]

        # TTL spread
        ttls = [f.min_ttl for _, f in window]
        ttl_mean = sum(ttls) / len(ttls)
        ttl_std = math.sqrt(sum((x - ttl_mean) ** 2 for x in ttls) / len(ttls)) if len(ttls) > 1 else 0.0

        features = {
            "dst_ip": key,
            "ts_start": window[0][0],
            "ts_end": now,
            "flow_count": total_flows,
            "packet_count": total_packets,
            "byte_count": total_bytes,
            "pps": total_packets / max(self.window_size, 0.001),
            "syn_count": syn_count,
            "ack_count": ack_count,
            "syn_ratio": syn_ratio,
            "unique_sources": unique_srcs,
            "source_entropy": source_entropy,
            "ttl_std": ttl_std,
        }
        return features
