"""
Scenario Orchestration & PCAP Generator.
Combines benign background streams with targeted threat vectors.
Exports to real PCAP files via Scapy and provides in-memory streaming pipelines.
"""

import os
import time
from typing import List, Dict, Any, Optional

from scapy.all import IP, TCP, UDP, Raw, DNS, DNSQR, wrpcap

from ingestion.schema import PacketRecord
from traffic_simulator.benign_generator import BenignTrafficGenerator
from traffic_simulator.scan_simulator import ScanTrafficGenerator
from traffic_simulator.flood_simulator import FloodTrafficGenerator
from traffic_simulator.slowloris_simulator import SlowlorisTrafficGenerator
from traffic_simulator.dns_anomaly_simulator import DNSAnomalyTrafficGenerator
from traffic_simulator.beacon_simulator import BeaconTrafficGenerator


class ScenarioManager:
    """Orchestrates test scenarios for SIH 2026 Problem Statement 26145."""

    def __init__(self, pcap_dir: str = "data/raw_pcaps"):
        self.pcap_dir = pcap_dir
        os.makedirs(self.pcap_dir, exist_ok=True)

    def generate_scenario(
        self,
        scenario_name: str,
        benign_count: int = 60,
        attack_intensity: int = 40,
        base_timestamp: Optional[float] = None
    ) -> List[PacketRecord]:
        """
        Generates an interleaved sequence of benign and attack packets.
        scenario_name options: 'all', 'benign', 'port_scan', 'syn_flood',
                              'udp_flood', 'slowloris', 'dns_tunneling', 'c2_beaconing'
        """
        t = base_timestamp or time.time()
        benign_gen = BenignTrafficGenerator(base_timestamp=t)
        all_packets = benign_gen.generate_packets(count=benign_count)

        attack_packets = []

        if scenario_name in ["port_scan", "all"]:
            scan_gen = ScanTrafficGenerator(attacker_ip="192.168.10.201", target_ip="10.0.0.50")
            attack_packets.extend(scan_gen.generate_rapid_syn_scan(t + 2.0, port_count=attack_intensity))

        if scenario_name in ["syn_flood", "all"]:
            flood_gen = FloodTrafficGenerator(attacker_ip="192.168.10.220", target_ip="10.0.0.80")
            attack_packets.extend(flood_gen.generate_syn_flood(t + 5.0, count=attack_intensity * 2))

        if scenario_name in ["udp_flood", "all"]:
            flood_gen = FloodTrafficGenerator(attacker_ip="192.168.10.225", target_ip="10.0.0.80")
            attack_packets.extend(flood_gen.generate_udp_flood(t + 7.0, count=attack_intensity * 2))

        if scenario_name in ["slowloris", "all"]:
            slow_gen = SlowlorisTrafficGenerator(attacker_ip="192.168.10.210", target_ip="10.0.0.80")
            attack_packets.extend(slow_gen.generate_slowloris_attack(t + 3.0, connections=6, headers_per_conn=5))

        if scenario_name in ["dns_tunneling", "all"]:
            dns_gen = DNSAnomalyTrafficGenerator(attacker_ip="192.168.10.180", dns_server="8.8.8.8")
            attack_packets.extend(dns_gen.generate_dns_tunneling(t + 4.0, query_count=attack_intensity))

        if scenario_name in ["c2_beaconing", "all"]:
            beacon_gen = BeaconTrafficGenerator(
                infected_ip="192.168.10.155",
                c2_server="198.51.100.77",
                interval_sec=4.0,
                jitter_pct=0.15
            )
            attack_packets.extend(beacon_gen.generate_beacons(t + 1.0, beacon_count=8))

        all_packets.extend(attack_packets)
        all_packets.sort(key=lambda p: p.timestamp)
        return all_packets

    def export_to_pcap(self, packets: List[PacketRecord], output_filename: str) -> str:
        """
        Converts internal PacketRecord models into Scapy IP packets and writes a standard PCAP file.
        Can be opened directly with Wireshark, Zeek, or Suricata.
        """
        scapy_pkts = []
        for p in packets:
            proto_layer = None
            if p.protocol == "TCP":
                flags = "".join(f[0] for f in p.tcp_flags) if p.tcp_flags else "S"
                proto_layer = TCP(sport=p.src_port, dport=p.dst_port, flags=flags)
                if p.payload_preview:
                    proto_layer = proto_layer / Raw(load=p.payload_preview.encode(errors="ignore"))
            elif p.protocol == "UDP":
                if p.dns_query:
                    proto_layer = UDP(sport=p.src_port, dport=p.dst_port) / DNS(
                        rd=1, qd=DNSQR(qname=p.dns_query, qtype=p.dns_qtype or "A")
                    )
                else:
                    payload = (p.payload_preview or "UDP payload").encode(errors="ignore")
                    proto_layer = UDP(sport=p.src_port, dport=p.dst_port) / Raw(load=payload)
            else:
                proto_layer = Raw(load=b"ICMP/Raw")

            scapy_pkt = IP(src=p.src_ip, dst=p.dst_ip) / proto_layer
            scapy_pkt.time = p.timestamp
            scapy_pkts.append(scapy_pkt)

        filepath = os.path.join(self.pcap_dir, output_filename)
        wrpcap(filepath, scapy_pkts)
        return filepath
