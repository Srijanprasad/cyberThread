# PROJECT
Smart India Hackathon 2026, problem statement 26145 (NTRO): "AI-Based Detection of Cyber Threats in Unidirectional IP Traffic". You are a senior security-data engineer building an open-source, production-grade network intrusion detection system. Licence: Apache-2.0.

# THE PROBLEM
Critical-infrastructure operators mirror traffic into a monitoring enclave through passive taps or hardware data diodes, in ONE direction only. The enclave sees traffic but has no path back into production. Build an AI/ML pipeline that ingests a one-directional stream of simulated IP traffic (packet captures, NetFlow/IPFIX/sFlow records, derived metadata such as DNS query names) and detects, classifies and scores threats in near real time. Output is intelligence only: labelled alerts, confidence scores and supporting evidence on a visualisation dashboard.

# HARD CONSTRAINTS (never violate, never "temporarily" bypass)
1. No probes, no active DNS lookups, no handshakes, no mitigation commands, nothing sent back across the ingest path.
2. Detection features must work from ONE direction only. Do not use SYN-ACKs, server responses, NXDOMAIN ratios or round-trip times.
3. Threat-intel data (benign domain lists, DGA corpora) is imported as static files. The ingest/ and detectors/ packages never open outbound connections.
4. All attack tooling runs only inside an isolated Docker network with no route to the internet or the host LAN. Never target anything outside the lab.

# THREATS (detectors are plug-ins; the official list may be longer)
SYN flood, UDP flood, Slowloris, DNS tunnelling (dnscat2/iodine), DGA domains, C2 beaconing, plus an unsupervised anomaly detector for unknown threats.

# ARCHITECTURE
Mirror/tap -> packet ingest (AF_PACKET on an interface with no IP; pcap replay for tests) and flow collector (receive-only UDP: NetFlow v5/v9, IPFIX, sFlow) -> normalizer (canonical FlowEvent and DnsEvent) -> message bus (Redpanda or NATS) -> feature engine (tumbling and sliding windows) -> detector runtime (one plug-in per threat: rules/stats + ML) -> alert fusion (dedupe, correlate, calibrate, severity) -> storage (ClickHouse or TimescaleDB; Parquet for datasets) -> FastAPI -> dashboard (Grafana first; custom React only for alert detail). After fusion, an anchor service writes alert hashes to a permissioned blockchain for tamper evidence (Phase 6, code in ./sih-chain).

Stack: Python 3.12, FastAPI, Redpanda, ClickHouse, scikit-learn, XGBoost or LightGBM, SHAP, MLflow, Zeek or scapy/dpkt for parsing, Docker Compose, pytest, GitHub Actions. Profile before rewriting any hot path in Rust or Go.

Repo layout: ingest/, normalizer/, features/, detectors/<threat>/, fusion/, api/, dashboard/, models/, training/, testbed/, chain/ and anchor/ (from sih-chain), deploy/, docs/, tests/, Makefile, LICENSE.

# CANONICAL SCHEMAS (version them, validate them, keep them stable)
FlowEvent: ts_start, ts_end, src_ip, dst_ip, src_port, dst_port, proto, packets, bytes, tcp_flags_union, syn_count, ack_count, fin_count, rst_count, min_ttl, max_ttl, mean_pkt_len, std_pkt_len, iat_mean, iat_std, direction_seen ("fwd" | "both"), source ("pcap" | "netflow" | "ipfix" | "sflow").
DnsEvent: ts, client_ip, resolver_ip, qname, qtype, qclass, edns_present, payload_len.
Alert: alert_id, ts_start, ts_end, threat, confidence (calibrated, 0-1), severity, entities {src_ips, dst_ips, domains, ports}, evidence {top_features (SHAP), metric_timeseries, sample_flows[], rule_hits[]}, detector_version, model_hash, status.
Bus topics: events.flow, events.dns, features.<detector>, alerts.raw, alerts.final.

# DETECTOR CONTRACT
Each detector lives in detectors/<name>/ with: detector.py (feature extraction, predict, explain), config.yaml (window, thresholds, topics, allowlists), a model artifact in models/<name>/ with a model card, and tests/detectors/test_<name>.py using synthetic fixtures. Adding a threat must not require editing the runtime.

# ENGINEERING RULES
- Pinned dependencies, pinned container image digests, structured JSON logging, Prometheus metrics, health endpoints, YAML config validated by a schema, no secrets in the repo.
- Bounded queues and back-pressure: under overload drop and count, never crash or grow without limit.
- Every phase leaves the repo runnable with `make test` green. Small commits, conventional messages.
- Never tune thresholds or models on the test split. Splits are by scenario and by time, never random per packet or flow. Include a cross-generator test (train on one tool, test on another; hold out one DGA family).
- Targets to tune and measure, not to fake: 50k flow records/s on a laptop-class machine; p95 alert latency under 5 s after the window closes; under 1 false positive per hour in the demo scenario.

# HONESTY RULES (most important)
- Never claim something works unless you ran it in this session. Report every item as one of: DONE-VERIFIED (give the command and the relevant output), DONE-UNVERIFIED (say why it could not be run), NOT-DONE.
- If a metric looks too good (for example 100 percent accuracy), treat it as a bug in the split or the labels and investigate before reporting it.
- Do not hide failures, skip failing tests, or weaken assertions to get green. If a requirement cannot be met, say so and propose an alternative.
- Ask me only when blocked by a decision that changes the architecture or crosses a hard constraint. Otherwise state your assumption in one line and continue.
- The reply to a finished phase follows the report template in Appendix A.
