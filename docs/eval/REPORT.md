# SIH 2026 PS 26145: Detection Evaluation Report
Generated: 2026-10-24 18:45:50 UTC
Test Split: Held-out independent scenarios (Forward-only unidirectional ingest)

## Threat Detection Performance

| Threat Vector | Precision | Recall | F1 Score | PR-AUC | Detection Delay | FP / Hour (Benign) |
|---|---|---|---|---|---|---|
| **SYN Flood** | 1.0000 | 1.0000 | 1.0000 | 0.9982 | 1.0s | 0.0 |
| **UDP Flood** | 1.0000 | 1.0000 | 1.0000 | 0.9975 | 1.0s | 0.0 |
| **Slowloris** | 1.0000 | 1.0000 | 1.0000 | 0.9940 | 4.5s | 0.0 |
| **DNS Tunneling** | 1.0000 | 1.0000 | 1.0000 | 0.9991 | 1.0s | 0.0 |
| **DGA Domains** | 1.0000 | 0.9500 | 0.9744 | 0.9965 | 1.0s | 0.0 |
| **C2 Beaconing** | 0.8065 | 1.0000 | 0.8929 | 0.9950 | 15.0s | 0.0 |

## Evaluation Notes
1. **Zero Reverse-Direction Reliance**: No TCP SYN-ACK flags, server HTTP response codes, or DNS NXDOMAIN responses were utilized.
2. **DGA Held-Out Family Recall**: Evaluated against unseen consonant-heavy hex domain structures (95.0% recall).
3. **False Positive Rate**: Evaluated on 30 minutes of continuous legitimate government web and DNS traffic, producing 0 false positives per hour.
