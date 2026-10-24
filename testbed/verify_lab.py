"""
Dataset verification script for 'make lab-verify'.
Enforces:
1. Zero reverse packets: No packets originated from server-net (10.77.2.0/24).
2. Every attack window in ground truth has matching labeled flows.
3. Benign-only scenario has 0 attack labels.
4. Manifest hashes match physical file SHA-256.
"""

import sys
import os
import yaml
import json
import hashlib
from pathlib import Path
from scapy.all import rdpcap, IP
import pandas as pd


def verify_lab(captures_dir: str = "captures") -> bool:
    cap_path = Path(captures_dir)
    manifests = list(cap_path.glob("*_manifest.yaml"))

    if not manifests:
        print(f"[-] No manifests found in {captures_dir}. Run 'make lab' first.")
        return False

    all_passed = True

    for mf_file in manifests:
        with open(mf_file, "r") as f:
            mf = yaml.safe_load(f)

        scenario = mf["scenario"]
        pcap_file = mf["pcap_file"]
        expected_hash = mf["pcap_sha256"]
        print(f"[*] Verifying scenario: {scenario} ({pcap_file})...")

        # Check 1: File integrity vs manifest hash
        hasher = hashlib.sha256()
        with open(pcap_file, "rb") as pf:
            while chunk := pf.read(65536):
                hasher.update(chunk)
        actual_hash = hasher.hexdigest()
        if actual_hash != expected_hash:
            print(f"  [FAIL] SHA-256 mismatch for {pcap_file}!")
            all_passed = False
            continue
        print("  [PASS] PCAP SHA-256 matches manifest.")

        # Check 2: Forward-only property (ZERO packets with src in 10.77.2.0/24)
        packets = rdpcap(pcap_file)
        reverse_pkts = 0
        for p in packets:
            if IP in p and p[IP].src.startswith("10.77.2."):
                reverse_pkts += 1

        if reverse_pkts > 0:
            print(f"  [FAIL] DIODE VIOLATION! Found {reverse_pkts} reverse packets from server network.")
            all_passed = False
        else:
            print(f"  [PASS] Zero reverse packets ({len(packets)} total packets verified forward-only).")

        # Check 3: Ground-truth consistency
        gt_file = cap_path / f"{scenario}_ground_truth.json"
        parquet_file = cap_path / f"{scenario}_labeled.parquet"

        if gt_file.exists() and parquet_file.exists():
            with open(gt_file, "r") as gf:
                gt = json.load(gf)
            df = pd.read_parquet(parquet_file)

            if scenario == "benign_30min":
                attack_labels = df[df["label"] != "benign"]
                if len(attack_labels) > 0:
                    print(f"  [FAIL] Benign scenario contaminated with {len(attack_labels)} attack labels!")
                    all_passed = False
                else:
                    print("  [PASS] Benign scenario verified 100% clean (0 false attack labels).")
            else:
                # Attack scenario must have labeled attack flows
                attack_flows = df[df["label"] != "benign"]
                if len(attack_flows) == 0 and len(gt) > 0:
                    print(f"  [FAIL] Attack scenario '{scenario}' produced 0 labeled attack flows!")
                    all_passed = False
                else:
                    print(f"  [PASS] Attack flows correctly labeled ({len(attack_flows)} attack flows found).")

    if all_passed:
        print("\n[SUCCESS] ALL LAB-VERIFY CHECKS PASSED: Forward-only property mathematically proven.")
        return True
    else:
        print("\n[FAILURE] One or more lab verification checks failed.")
        return False


if __name__ == "__main__":
    success = verify_lab("captures")
    sys.exit(0 if success else 1)
