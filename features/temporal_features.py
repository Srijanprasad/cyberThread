"""
Innovation 2: Multi-Window Behavioral Fusion & Temporal Analytics.
Maintains short (1-5s), medium (30-60s), and long (5-30m) behavioral windows per host.
Includes jittered C2 beaconing detection (periodicity/autocorrelation) and streaming change-point detection.
"""

import time
import numpy as np
from collections import defaultdict, deque
from typing import Dict, List, Any, Tuple, Optional
from ingestion.schema import PacketRecord, FlowRecord


class MultiWindowTracker:
    """
    Maintains multi-timescale temporal rolling state for all active endpoints.
    Short window: 5s (floods, bursts)
    Medium window: 60s (scans, DNS bursts)
    Long window: 600s / 10m (stealth scans, C2 beaconing)
    """

    def __init__(
        self,
        short_window_sec: float = 5.0,
        medium_window_sec: float = 60.0,
        long_window_sec: float = 600.0,
    ):
        self.short_win = short_window_sec
        self.med_win = medium_window_sec
        self.long_win = long_window_sec

        # host -> deque of (timestamp, dst_ip, dst_port, protocol, packet_count, byte_count)
        self.host_events: Dict[str, deque] = defaultdict(lambda: deque(maxlen=2000))

        # host:dst_ip -> deque of timestamps for beaconing periodicity
        self.beacon_pairs: Dict[Tuple[str, str], deque] = defaultdict(lambda: deque(maxlen=200))

        # Moving average baselines per host for change-point detection
        self.host_pps_ema: Dict[str, float] = defaultdict(float)
        self.alpha_ema = 0.1  # smoothing factor

    def record_packet(self, pkt: PacketRecord):
        """Records raw packet event into multi-timescale buffers."""
        t = pkt.timestamp
        is_syn = "SYN" in pkt.tcp_flags
        self.host_events[pkt.src_ip].append(
            (t, pkt.dst_ip, pkt.dst_port, pkt.protocol, 1, pkt.length, is_syn)
        )
        # Record destination pair for beacon analysis (only on new session or UDP query)
        if is_syn or pkt.protocol == "UDP":
            self.beacon_pairs[(pkt.src_ip, pkt.dst_ip)].append(t)

    def record_flow(self, flow: FlowRecord):
        """Records aggregated flow event (no-op for raw host_events to prevent double counting)."""
        pass

    def get_multi_window_features(self, src_ip: str, current_time: float) -> Dict[str, float]:
        """
        Extracts fused multi-window statistics for a given source host.
        """
        events = self.host_events.get(src_ip, deque())
        if not events:
            return {
                "short_pps": 0.0,
                "short_unique_ports": 0.0,
                "short_unique_ips": 0.0,
                "med_unique_ports": 0.0,
                "med_unique_ips": 0.0,
                "long_unique_ports": 0.0,
                "long_unique_ips": 0.0,
                "change_point_ratio": 1.0,
                "max_beacon_periodicity": 0.0,
            }

        short_cutoff = current_time - self.short_win
        med_cutoff = current_time - self.med_win
        long_cutoff = current_time - self.long_win

        short_pkts = 0
        short_syn_pkts = 0
        short_ports = set()
        short_ips = set()

        med_ports = set()
        med_ips = set()

        long_ports = set()
        long_ips = set()

        # Iterate events in reverse (from most recent)
        for event in reversed(events):
            t = event[0]
            if t < long_cutoff:
                break
            dst_ip = event[1]
            dst_port = event[2]
            proto = event[3]
            pkts = event[4]
            bytes_ = event[5]
            is_syn = event[6] if len(event) > 6 else False

            long_ports.add(dst_port)
            long_ips.add(dst_ip)

            if t >= med_cutoff:
                med_ports.add(dst_port)
                med_ips.add(dst_ip)

            if t >= short_cutoff:
                short_pkts += pkts
                if is_syn:
                    short_syn_pkts += pkts
                short_ports.add(dst_port)
                short_ips.add(dst_ip)

        short_pps = short_pkts / self.short_win

        # Streaming Change-Point Ratio:
        # Detects sudden burst before long-term baseline catches up
        prev_ema = self.host_pps_ema[src_ip]
        if prev_ema > 0.0:
            change_point_ratio = short_pps / max(0.5, prev_ema)
        else:
            change_point_ratio = 1.0

        # Update EMA
        self.host_pps_ema[src_ip] = (self.alpha_ema * short_pps) + ((1.0 - self.alpha_ema) * prev_ema)

        # Check maximum beacon periodicity score among all target destinations of this host
        max_periodicity = 0.0
        for (h, dst), times in list(self.beacon_pairs.items()):
            if h == src_ip and len(times) >= 4:
                p_score = self._compute_periodicity(list(times), current_time)
                if p_score > max_periodicity:
                    max_periodicity = p_score

        return {
            "short_pps": float(short_pps),
            "short_pkts": float(short_pkts),
            "short_syn_pkts": float(short_syn_pkts),
            "short_unique_ports": float(len(short_ports)),
            "short_unique_ips": float(len(short_ips)),
            "med_unique_ports": float(len(med_ports)),
            "med_unique_ips": float(len(med_ips)),
            "long_unique_ports": float(len(long_ports)),
            "long_unique_ips": float(len(long_ips)),
            "change_point_ratio": float(min(100.0, change_point_ratio)),
            "max_beacon_periodicity": float(max_periodicity),
        }

    def _compute_periodicity(self, timestamps: List[float], current_time: float) -> float:
        """
        Computes periodicity score (0.0 to 1.0) resilient to jitter.
        Uses Coefficient of Variation (CV) of Inter-Arrival Times (IAT).
        Standard C2 beacons (Cobalt Strike, Sliver) apply 10-30% jitter.
        CV = std(IAT) / mean(IAT).
        Lower CV indicates strong regularity.
        """
        recent_ts = [t for t in timestamps if (current_time - t) <= self.long_win]
        if len(recent_ts) < 4:
            return 0.0

        iats = np.diff(np.sort(recent_ts))
        if len(iats) < 3 or np.mean(iats) < 0.2:
            # Skip if rate is too fast (floods or bulk transfers)
            return 0.0

        mean_iat = np.mean(iats)
        std_iat = np.std(iats)
        cv = std_iat / (mean_iat + 1e-6)

        # CV < 0.15: Almost perfectly periodic (Score: 0.95 - 1.0)
        # CV < 0.35: Periodic with ~20-30% jitter (Score: 0.80 - 0.95)
        # CV < 0.50: Moderate periodicity (Score: 0.60 - 0.80)
        # CV >= 0.50: Poisson or bursty (Score: 0.0 - 0.5)
        if cv < 0.15:
            score = 1.0
        elif cv < 0.40:
            score = 0.95 - ((cv - 0.15) / 0.25) * 0.20
        elif cv < 0.70:
            score = 0.75 - ((cv - 0.40) / 0.30) * 0.45
        else:
            score = max(0.0, 0.30 - (cv - 0.70))

        return float(np.clip(score, 0.0, 1.0))
