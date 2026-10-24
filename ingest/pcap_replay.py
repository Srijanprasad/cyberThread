"""
PCAP Replay Ingest Reader for SIH 2026 PS 26145.
Preserves event-time timestamps accurately.
Supports 1x, 10x, and 0 (as-fast-as-possible) replay speed factors.
Zero outbound sockets. Passive ingest only.
"""

import time
from typing import Generator, Optional, Callable
from scapy.all import PcapReader, Packet


class PcapReplayReader:
    def __init__(self, pcap_path: str, speed_factor: float = 0.0):
        """
        speed_factor = 0.0 means as-fast-as-possible (analytical batching).
        speed_factor = 1.0 means real-time event-time synchronization.
        speed_factor = 10.0 means 10x accelerated playback.
        """
        self.pcap_path = pcap_path
        self.speed_factor = speed_factor
        self.packets_read = 0

    def read_packets(self) -> Generator[Packet, None, None]:
        """Yields scapy packets with optional event-time delay pacing."""
        reader = PcapReader(self.pcap_path)
        first_event_ts: Optional[float] = None
        first_wall_ts: Optional[float] = None

        try:
            for pkt in reader:
                self.packets_read += 1
                pkt_time = float(pkt.time)

                if self.speed_factor > 0:
                    if first_event_ts is None:
                        first_event_ts = pkt_time
                        first_wall_ts = time.time()
                    else:
                        event_elapsed = (pkt_time - first_event_ts) / self.speed_factor
                        wall_elapsed = time.time() - first_wall_ts
                        sleep_time = event_elapsed - wall_elapsed
                        if sleep_time > 0:
                            time.sleep(min(sleep_time, 0.5))

                yield pkt
        finally:
            reader.close()
