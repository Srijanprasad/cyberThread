"""
Orchestrator for SIH 2026 PS 26145 Testbed.
Executes scenarios, schedules benign traffic and attacks,
writes forward-only PCAPs, ground-truth logs, and manifests.
Strict constraint: Zero packets emitted from server network (10.77.2.0/24).
"""

import os
import sys
import time
import yaml
import json
import hashlib
import random
from pathlib import Path
from typing import Dict, Any, List

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap


class ScenarioOrchestrator:
    def __init__(self, scenario_path: str, output_dir: str = "captures"):
        with open(scenario_path, "r") as f:
            self.scenario = yaml.safe_load(f)

        self.scenario_name = self.scenario.get("name", "unknown")
        self.seed = self.scenario.get("seed", 42)
        random.seed(self.seed)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.ground_truth: List[Dict[str, Any]] = []
        self.packets = []
        self.start_time = 1700000000.0  # Normalized reference epoch

    def run(self) -> Dict[str, Any]:
        """Runs the scenario generation and produces PCAP + ground truth."""
        duration = float(self.scenario.get("duration", 60.0))
        benign_profile = self.scenario.get("benign_profile", {})
        attacks = self.scenario.get("attacks", [])

        # 1. Generate Benign Traffic
        self._generate_benign(duration, benign_profile)

        # 2. Schedule and Generate Attacks
        for atk in attacks:
            self._generate_attack(atk)

        # 3. Sort packets monotonically by time
        self.packets.sort(key=lambda p: p.time)

        # 4. Strict Forward-Only Verification: Drop any accidental reverse packets
        forward_only_packets = []
        for p in self.packets:
            if IP in p:
                src = p[IP].src
                if src.startswith("10.77.2."):
                    # Violates one-way optical diode property! Server response leaked!
                    continue
            forward_only_packets.append(p)
        self.packets = forward_only_packets

        # 5. Write PCAP
        pcap_path = self.output_dir / f"{self.scenario_name}.pcap"
        wrpcap(str(pcap_path), self.packets)

        # 6. Compute SHA-256
        hasher = hashlib.sha256()
        with open(pcap_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        pcap_hash = hasher.hexdigest()

        # 7. Write Ground Truth
        gt_path = self.output_dir / f"{self.scenario_name}_ground_truth.json"
        with open(gt_path, "w") as f:
            json.dump(self.ground_truth, f, indent=2)

        # 8. Write Manifest
        manifest = {
            "scenario": self.scenario_name,
            "seed": self.seed,
            "duration": duration,
            "pcap_file": str(pcap_path),
            "pcap_sha256": pcap_hash,
            "total_packets": len(self.packets),
            "attack_count": len(self.ground_truth),
            "diode_forward_only_guarantee": True,
            "timestamp": time.time(),
        }
        manifest_path = self.output_dir / f"{self.scenario_name}_manifest.yaml"
        with open(manifest_path, "w") as f:
            yaml.dump(manifest, f)

        return manifest

    def _generate_benign(self, duration: float, profile: Dict[str, Any]):
        http_rate = profile.get("http_rate", 10.0)
        dns_rate = profile.get("dns_rate", 5.0)

        # Generate benign HTTP client traffic
        num_http = int(duration * http_rate)
        for _ in range(num_http):
            t = self.start_time + random.uniform(0, duration)
            src_ip = f"10.77.1.{random.randint(10, 60)}"
            dst_ip = "10.77.2.10"
            sport = random.randint(10000, 60000)
            payload = f"GET /index.html HTTP/1.1\r\nHost: portal.intra\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode()
            pkt = IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=80, flags="PA", seq=random.randint(1000, 90000)) / Raw(load=payload)
            pkt.time = t
            self.packets.append(pkt)

        # Generate benign DNS queries
        benign_domains = ["gov.in", "nic.in", "nciipc.gov.in", "cert-in.org.in", "meity.gov.in", "isro.gov.in"]
        num_dns = int(duration * dns_rate)
        for _ in range(num_dns):
            t = self.start_time + random.uniform(0, duration)
            src_ip = f"10.77.1.{random.randint(10, 60)}"
            dst_ip = "10.77.2.53"
            sport = random.randint(10000, 60000)
            domain = random.choice(benign_domains)
            pkt = IP(src=src_ip, dst=dst_ip, ttl=64) / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=domain, qtype="A"))
            pkt.time = t
            self.packets.append(pkt)

    def _generate_attack(self, atk: Dict[str, Any]):
        atk_type = atk.get("type")
        start_offset = atk.get("start_offset", 10.0)
        atk_duration = atk.get("duration", 20.0)
        t_start = self.start_time + start_offset
        t_end = t_start + atk_duration

        record = {
            "attack_id": atk.get("id"),
            "type": atk_type,
            "start_time": t_start,
            "end_time": t_end,
            "target_ip": atk.get("target_ip"),
            "target_port": atk.get("target_port"),
            "attacker_ip": atk.get("attacker_ip"),
            "parameters": atk,
        }
        self.ground_truth.append(record)

        if atk_type == "syn_flood":
            rate = atk.get("rate_pps", 2000)
            count = int(atk_duration * min(rate, 250))  # Capped for fast execution
            for i in range(count):
                t = t_start + (i / count) * atk_duration
                if atk.get("source_mode") == "random_spoofed":
                    src = f"10.77.1.{random.randint(2, 250)}"
                else:
                    src = atk.get("attacker_ip", "10.77.1.105")
                sport = random.randint(1024, 65535)
                pkt = IP(src=src, dst=atk.get("target_ip", "10.77.2.10"), ttl=random.choice([64, 128])) / TCP(sport=sport, dport=atk.get("target_port", 80), flags="S", seq=random.randint(1000, 50000))
                pkt.time = t
                self.packets.append(pkt)

        elif atk_type == "udp_flood":
            rate = atk.get("rate_pps", 2000)
            count = int(atk_duration * min(rate, 250))
            payload = b"X" * atk.get("payload_size", 512)
            for i in range(count):
                t = t_start + (i / count) * atk_duration
                src = atk.get("attacker_ip", "10.77.1.150")
                sport = random.randint(1024, 65535)
                pkt = IP(src=src, dst=atk.get("target_ip", "10.77.2.53"), ttl=64) / UDP(sport=sport, dport=atk.get("target_port", 53)) / Raw(load=payload)
                pkt.time = t
                self.packets.append(pkt)

        elif atk_type == "slowloris":
            concurrency = atk.get("concurrency", 50)
            for conn_id in range(concurrency):
                sport = 15000 + conn_id
                src = atk.get("attacker_ip", "10.77.1.80")
                dst = atk.get("target_ip", "10.77.2.10")
                # SYN
                p_syn = IP(src=src, dst=dst) / TCP(sport=sport, dport=80, flags="S", seq=100)
                p_syn.time = t_start + conn_id * 0.05
                self.packets.append(p_syn)
                # Drip HTTP headers every 10-15s
                intervals = int(atk_duration / 12.0)
                for step in range(intervals):
                    p_drip = IP(src=src, dst=dst) / TCP(sport=sport, dport=80, flags="PA", seq=101 + step * 20) / Raw(load=f"X-Drip-{step}: {random.randint(100,999)}\r\n".encode())
                    p_drip.time = t_start + step * 12.0 + conn_id * 0.01
                    self.packets.append(p_drip)

        elif atk_type == "dns_tunnel":
            rate = atk.get("rate_qps", 15.0)
            count = int(atk_duration * rate)
            parent = atk.get("parent_domain", "tunnel.covert.org")
            for i in range(count):
                t = t_start + (i / count) * atk_duration
                encoded = hashlib.md5(f"chunk_{i}".encode()).hexdigest() + "a9f8b7c6d5e4"
                qname = f"{encoded}.{parent}"
                pkt = IP(src=atk.get("attacker_ip", "10.77.1.66"), dst=atk.get("target_ip", "10.77.2.53")) / UDP(sport=random.randint(10000, 60000), dport=53) / DNS(rd=1, qd=DNSQR(qname=qname, qtype="TXT"))
                pkt.time = t
                self.packets.append(pkt)

        elif atk_type == "c2_beacon":
            interval = atk.get("interval", 15.0)
            jitter = atk.get("jitter", 0.1)
            t = t_start
            while t < t_end:
                src = atk.get("attacker_ip", "10.77.1.44")
                dst = atk.get("target_ip", "10.77.2.99")
                sport = random.randint(10000, 60000)
                pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=atk.get("target_port", 8443), flags="S", seq=random.randint(1000, 9000))
                pkt.time = t
                self.packets.append(pkt)
                delta = interval * (1.0 + random.uniform(-jitter, jitter))
                t += delta

        elif atk_type == "dga":
            rate = atk.get("rate_qps", 10.0)
            count = int(atk_duration * rate)
            for i in range(count):
                t = t_start + (i / count) * atk_duration
                # Pseudo-random pseudo-pronounceable or hex DGA domain
                sub = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=14))
                qname = f"{sub}.cc"
                pkt = IP(src=atk.get("attacker_ip", "10.77.1.180"), dst=atk.get("target_ip", "10.77.2.53")) / UDP(sport=random.randint(10000, 60000), dport=53) / DNS(rd=1, qd=DNSQR(qname=qname, qtype="A"))
                pkt.time = t
                self.packets.append(pkt)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python orchestrator.py <scenario_yaml> [output_dir]")
        sys.exit(1)
    sc_file = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "captures"
    orch = ScenarioOrchestrator(sc_file, out_dir)
    res = orch.run()
    print(f"Generated scenario '{res['scenario']}' -> {res['pcap_file']} ({res['total_packets']} pkts, hash: {res['pcap_sha256'][:12]}...)")
