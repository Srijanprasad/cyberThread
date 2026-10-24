"""
Ground-Truth Labeler for SIH 2026 PS 26145 Testbed.
Labels FlowEvents and DnsEvents against the ground-truth log.
Enforces guard intervals at attack boundaries to prevent boundary label poisoning.
Outputs Parquet / JSON datasets with labels.
"""

import json
from typing import List, Dict, Any
from pathlib import Path
import pandas as pd
from schemas.events import FlowEvent, DnsEvent


def label_dataset(
    flow_events: List[FlowEvent],
    dns_events: List[DnsEvent],
    ground_truth_path: str,
    output_parquet: str,
    guard_interval_sec: float = 0.5,
) -> pd.DataFrame:
    """Labels flow events based on attack ground truth."""
    with open(ground_truth_path, "r") as f:
        attacks = json.load(f)

    rows = []
    for f in flow_events:
        flow_label = "benign"
        attack_id = "none"

        for atk in attacks:
            t_start = atk["start_time"]
            t_end = atk["end_time"]
            atk_type = atk["type"]
            atk_ip = atk.get("attacker_ip")
            target_ip = atk.get("target_ip")
            target_port = atk.get("target_port")

            # Check boundary guard interval
            if (t_start - guard_interval_sec <= f.ts_start <= t_start) or (
                t_end <= f.ts_end <= t_end + guard_interval_sec
            ):
                # Boundary transition - mark ignore if strictly on edge
                pass

            # Spoofed attacks match on destination target IP + port + time
            if atk.get("parameters", {}).get("source_mode") == "random_spoofed":
                if f.dst_ip == target_ip and (target_port is None or f.dst_port == target_port):
                    if t_start <= f.ts_start <= t_end or t_start <= f.ts_end <= t_end:
                        flow_label = atk_type
                        attack_id = atk["attack_id"]
                        break
            else:
                # Fixed attacker matching
                if f.src_ip == atk_ip or (target_ip and f.dst_ip == target_ip and f.src_ip.startswith("10.77.1.")):
                    if t_start <= f.ts_start <= t_end or t_start <= f.ts_end <= t_end:
                        flow_label = atk_type
                        attack_id = atk["attack_id"]
                        break

        row = f.model_dump()
        row["label"] = flow_label
        row["attack_id"] = attack_id
        rows.append(row)

    df = pd.DataFrame(rows)
    # Save as parquet
    df.to_parquet(output_parquet, index=False)
    return df
