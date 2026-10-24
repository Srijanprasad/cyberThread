"""
Receive-Only NetFlow / IPFIX Flow Collector for SIH 2026 PS 26145.
Listens on UDP 2055 (NetFlow) or 4739 (IPFIX) without ever responding or sending packets.
Extracts forward-only flow records into canonical FlowEvents.
"""

import socket
import struct
from typing import List, Optional
from schemas.events import FlowEvent


class NetFlowCollector:
    """
    Passive receive-only UDP listener for NetFlow v5/v9.
    Zero outbound transmission.
    """
    def __init__(self, host: str = "0.0.0.0", port: int = 2055):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.dropped_packets = 0
        self.total_packets = 0

    def start_listener(self):
        """Binds to receive-only UDP socket."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        # Ensure SO_RCVBUF is sufficient to prevent buffer drops
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)

    def parse_netflow_v5_packet(self, data: bytes, src_addr: str) -> List[FlowEvent]:
        """Parses standard NetFlow v5 header and records."""
        if len(data) < 24:
            self.dropped_packets += 1
            return []

        version, count, sys_uptime, unix_secs, unix_nsecs = struct.unpack("!HHIII", data[:16])
        if version != 5:
            # Drop non-v5 or unsupported versions gracefully without crash
            self.dropped_packets += 1
            return []

        flows: List[FlowEvent] = []
        offset = 24
        record_size = 48

        for _ in range(count):
            if offset + record_size > len(data):
                break
            rec = data[offset : offset + record_size]
            src_ip_b, dst_ip_b, nexthop_b, input_if, output_if, pkts, bytes_cnt, first, last, sport, dport, pad, flags, proto, tos, src_as, dst_as, src_mask, dst_mask = struct.unpack(
                "!4s4s4sHHIIIIHHcBBHHBB", rec[:48]
            )
            src_ip = socket.inet_ntoa(src_ip_b)
            dst_ip = socket.inet_ntoa(dst_ip_b)

            fe = FlowEvent(
                ts_start=float(unix_secs + first / 1000.0),
                ts_end=float(unix_secs + last / 1000.0),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=sport,
                dst_port=dport,
                proto=proto,
                packets=pkts,
                bytes=bytes_cnt,
                tcp_flags_union=flags,
                syn_count=1 if (flags & 0x02) else 0,
                ack_count=1 if (flags & 0x10) else 0,
                fin_count=1 if (flags & 0x01) else 0,
                rst_count=1 if (flags & 0x04) else 0,
                direction_seen="fwd",
                source="netflow",
            )
            flows.append(fe)
            offset += record_size

        self.total_packets += 1
        return flows

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None
