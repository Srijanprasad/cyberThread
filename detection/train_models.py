"""
Training and Evaluation Pipeline for Unidirectional Threat Models.
Generates balanced synthetic training scenarios, trains Random Forest & Isolation Forest,
evaluates precision/recall/F1 metrics, and saves model artifacts.
"""

import os
import json
import numpy as np
from typing import List, Dict, Tuple
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score

from ingestion.schema import PacketRecord, ThreatCategory, VisibilityMask
from traffic_simulator.benign_generator import BenignTrafficGenerator
from traffic_simulator.scan_simulator import ScanTrafficGenerator
from traffic_simulator.flood_simulator import FloodTrafficGenerator
from traffic_simulator.slowloris_simulator import SlowlorisTrafficGenerator
from traffic_simulator.dns_anomaly_simulator import DNSAnomalyTrafficGenerator
from traffic_simulator.beacon_simulator import BeaconTrafficGenerator
from features.flow_features import FlowAggregator
from features.temporal_features import MultiWindowTracker
from features.dns_features import extract_dns_features
from features.visibility_mask import VisibilityMaskEngine, FEATURE_NAMES
from detection.classifier import ThreatClassifier
from detection.anomaly_detector import AnomalyDetector


def extract_sample_features(
    packets: List[PacketRecord],
    aggregator: FlowAggregator,
    tracker: MultiWindowTracker,
    vis_engine: VisibilityMaskEngine,
) -> Tuple[np.ndarray, Dict[str, float]]:
    """Processes a packet batch and extracts the final flow feature vector."""
    flow = None
    for pkt in packets:
        tracker.record_packet(pkt)
        flow = aggregator.update(pkt)

    if flow is None:
        return np.zeros(len(FEATURE_NAMES)), {}

    tracker.record_flow(flow)
    t_stats = tracker.get_multi_window_features(flow.src_ip, flow.last_time)

    # DNS features
    dns_ent = flow.dns_entropy_max
    if flow.dns_query_count > 0:
        for pkt in packets:
            if pkt.dns_query:
                d_feat = extract_dns_features(pkt.dns_query, pkt.dns_qtype or "A")
                if d_feat["entropy"] > dns_ent:
                    dns_ent = d_feat["entropy"]

    total_pkts = max(1, flow.packet_count)
    raw_dict = {
        "packets_per_sec": flow.packets_per_sec,
        "bytes_per_sec": flow.bytes_per_sec,
        "mean_packet_size": flow.mean_packet_size,
        "std_packet_size": flow.std_packet_size,
        "iat_mean": flow.iat_mean,
        "iat_std": flow.iat_std,
        "syn_ratio": flow.syn_count / total_pkts,
        "ack_ratio": flow.ack_count / total_pkts,
        "fin_ratio": flow.fin_count / total_pkts,
        "dns_query_count": float(flow.dns_query_count),
        "dns_entropy_max": float(dns_ent),
        "dns_label_len_max": float(flow.dns_label_len_max),
        "dns_unique_subdomains": float(flow.dns_unique_subdomains),
        "http_incomplete_flag": 1.0 if flow.http_incomplete else 0.0,
        "flow_duration": flow.duration,
        "unique_dst_ports_short": t_stats.get("short_unique_ports", 1.0),
        "unique_dst_ips_short": t_stats.get("short_unique_ips", 1.0),
        "periodicity_score": t_stats.get("max_beacon_periodicity", 0.0),
    }

    vec, _, _ = vis_engine.extract_masked_features(raw_dict, VisibilityMask())
    return vec, raw_dict


def generate_training_dataset(samples_per_class: int = 150) -> Tuple[np.ndarray, List[str]]:
    """Generates synthetic dataset across all required threat categories."""
    X_list = []
    y_list = []
    vis_engine = VisibilityMaskEngine()

    print(f"[*] Generating {samples_per_class} samples per threat category...")

    base_time = 1700000000.0

    # 1. Benign Traffic
    for i in range(samples_per_class):
        agg = FlowAggregator()
        tracker = MultiWindowTracker()
        gen = BenignTrafficGenerator(base_timestamp=base_time + i * 50)
        pkts = gen.generate_packets(count=np.random.randint(15, 40))
        vec, _ = extract_sample_features(pkts, agg, tracker, vis_engine)
        X_list.append(vec)
        y_list.append(ThreatCategory.BENIGN.value)

    # 2. Port Scans
    for i in range(samples_per_class):
        agg = FlowAggregator()
        tracker = MultiWindowTracker()
        gen = ScanTrafficGenerator(attacker_ip=f"192.168.10.{i % 50 + 10}")
        if i % 2 == 0:
            pkts = gen.generate_rapid_syn_scan(base_time + i * 50, port_count=np.random.randint(15, 35))
        else:
            pkts = gen.generate_slow_stealth_scan(base_time + i * 50, probe_count=np.random.randint(10, 20))
        vec, _ = extract_sample_features(pkts, agg, tracker, vis_engine)
        X_list.append(vec)
        y_list.append(ThreatCategory.PORT_SCAN.value)

    # 3. SYN Floods
    for i in range(samples_per_class):
        agg = FlowAggregator()
        tracker = MultiWindowTracker()
        gen = FloodTrafficGenerator(attacker_ip=f"192.168.20.{i % 50 + 10}")
        pkts = gen.generate_syn_flood(base_time + i * 50, count=np.random.randint(50, 150))
        vec, _ = extract_sample_features(pkts, agg, tracker, vis_engine)
        X_list.append(vec)
        y_list.append(ThreatCategory.SYN_FLOOD.value)

    # 4. UDP Floods
    for i in range(samples_per_class):
        agg = FlowAggregator()
        tracker = MultiWindowTracker()
        gen = FloodTrafficGenerator(attacker_ip=f"192.168.30.{i % 50 + 10}")
        pkts = gen.generate_udp_flood(base_time + i * 50, count=np.random.randint(50, 150))
        vec, _ = extract_sample_features(pkts, agg, tracker, vis_engine)
        X_list.append(vec)
        y_list.append(ThreatCategory.UDP_FLOOD.value)

    # 5. Slowloris
    for i in range(samples_per_class):
        agg = FlowAggregator()
        tracker = MultiWindowTracker()
        gen = SlowlorisTrafficGenerator(attacker_ip=f"192.168.40.{i % 50 + 10}")
        pkts = gen.generate_slowloris_attack(
            base_time + i * 50,
            connections=np.random.randint(3, 7),
            headers_per_conn=np.random.randint(4, 7)
        )
        vec, _ = extract_sample_features(pkts, agg, tracker, vis_engine)
        X_list.append(vec)
        y_list.append(ThreatCategory.SLOWLORIS.value)

    # 6. DNS Tunneling
    for i in range(samples_per_class):
        agg = FlowAggregator()
        tracker = MultiWindowTracker()
        gen = DNSAnomalyTrafficGenerator(attacker_ip=f"192.168.50.{i % 50 + 10}")
        if i % 3 == 0:
            pkts = gen.generate_dga_burst(base_time + i * 50, query_count=np.random.randint(15, 30))
        else:
            pkts = gen.generate_dns_tunneling(base_time + i * 50, query_count=np.random.randint(20, 45))
        vec, _ = extract_sample_features(pkts, agg, tracker, vis_engine)
        X_list.append(vec)
        y_list.append(ThreatCategory.DNS_TUNNELING.value)

    # 7. C2 Beaconing
    for i in range(samples_per_class):
        agg = FlowAggregator()
        tracker = MultiWindowTracker()
        gen = BeaconTrafficGenerator(
            infected_ip=f"192.168.60.{i % 50 + 10}",
            interval_sec=np.random.uniform(3.0, 7.0),
            jitter_pct=np.random.uniform(0.05, 0.25)
        )
        pkts = gen.generate_beacons(base_time + i * 50, beacon_count=np.random.randint(6, 12))
        vec, _ = extract_sample_features(pkts, agg, tracker, vis_engine)
        X_list.append(vec)
        y_list.append(ThreatCategory.C2_BEACONING.value)

    X = np.array(X_list, dtype=np.float32)
    return X, y_list


def train_and_evaluate():
    """Executes model training, evaluation, and persists artifacts."""
    X, y = generate_training_dataset(samples_per_class=120)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    print(f"[*] Training dataset size: {len(X_train)} samples, Test size: {len(X_test)} samples")

    # 1. Train Supervised Classifier
    classifier = ThreatClassifier("models/threat_classifier.joblib")
    classifier.train(X_train, y_train)

    # 2. Train Unsupervised Anomaly Detector (fit strictly on benign samples)
    benign_indices = [idx for idx, label in enumerate(y_train) if label == ThreatCategory.BENIGN.value]
    X_benign = X_train[benign_indices]
    anomaly_detector = AnomalyDetector("models/anomaly_detector.joblib")
    anomaly_detector.train(X_benign)

    # 3. Evaluate Supervised Classifier on Held-Out Test Data
    y_pred = []
    for vec in X_test:
        cat, _, _ = classifier.predict(vec)
        y_pred.append(cat.value)

    rep = classification_report(y_test, y_pred, output_dict=True)
    overall_f1 = f1_score(y_test, y_pred, average="weighted")
    overall_prec = precision_score(y_test, y_pred, average="weighted")
    overall_rec = recall_score(y_test, y_pred, average="weighted")

    print("\n" + "=" * 50)
    print("CLASSIFICATION EVALUATION REPORT (HELD-OUT TEST SET)")
    print("=" * 50)
    print(classification_report(y_test, y_pred))

    # Calculate False Positive Rate on Benign Class
    benign_test_indices = [idx for idx, label in enumerate(y_test) if label == ThreatCategory.BENIGN.value]
    fp_count = sum(1 for idx in benign_test_indices if y_pred[idx] != ThreatCategory.BENIGN.value)
    fpr = fp_count / max(1, len(benign_test_indices))

    metrics_payload = {
        "timestamp": 1700000000.0,
        "sample_counts": {
            "train": len(X_train),
            "test": len(X_test),
        },
        "overall_metrics": {
            "weighted_precision": round(overall_prec, 4),
            "weighted_recall": round(overall_rec, 4),
            "weighted_f1_score": round(overall_f1, 4),
            "benign_false_positive_rate": round(fpr, 4),
        },
        "per_class_metrics": {
            cls: {
                "precision": round(rep[cls]["precision"], 4),
                "recall": round(rep[cls]["recall"], 4),
                "f1_score": round(rep[cls]["f1-score"], 4),
                "support": rep[cls]["support"],
            }
            for cls in rep if cls not in ["accuracy", "macro avg", "weighted avg"]
        },
        "feature_importances": classifier.get_feature_importances(),
    }

    with open("models/evaluation_report.json", "w") as f:
        json.dump(metrics_payload, f, indent=2)

    print(f"[*] Evaluation report successfully saved to models/evaluation_report.json")
    print(f"[*] Weighted F1-Score: {overall_f1:.4f} | False Positive Rate: {fpr:.4f}")


if __name__ == "__main__":
    train_and_evaluate()
