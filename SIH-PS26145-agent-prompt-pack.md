# SIH 2026 PS 26145: Agent Prompt Pack

A master prompt plus seven phase prompts for a coding agent (Claude Code or similar). The master prompt is the project's standing instructions; each phase prompt is one working session.

## How to use this pack

1. Put the repo in place and copy the `sih-chain` folder into it (it becomes `chain/` and `anchor/` in Phase 6).
2. Save **Part 0** as `CLAUDE.md` (or your agent's project-instructions file) so every session starts with it.
3. Start one session per phase and paste that phase's prompt. Do not start the next phase until you have read the previous report and the acceptance checks pass.
4. After each phase: read the diff, run the acceptance commands yourself, check the report against the template in Appendix A, then commit.
5. Use Appendix B as your own review checklist.

Honesty note on this pack: the targets (throughput, latency, false-positive rates) are goals to tune, not promises. The Besu network and Compose files in `sih-chain` were never run (no Docker was available when they were written), so Phase 6 tests them for the first time.

---

## Part 0: Master prompt (standing instructions)

~~~~text
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
~~~~

---

## Part 1: Phase 1 prompt (foundations and testbed)

~~~~text
# PHASE 1: Foundations, lab and labelled data

GOAL
A reproducible lab that produces labelled, forward-only traffic datasets for benign, SYN flood and UDP flood scenarios, plus the repo scaffolding everything else will sit on.

TASKS
1. Repo scaffolding: layout from CLAUDE.md, Apache-2.0 LICENSE, README stub, Makefile with targets lab, lab-verify, test, lint; GitHub Actions workflow running lint and tests; pre-commit config; pyproject with pinned dependencies.
2. Lab topology (testbed/compose.yml). Use TWO internal networks joined by a router container so that all client-to-server traffic crosses one place you can capture:
   - client-net 10.77.1.0/24 (benign clients and attackers), server-net 10.77.2.0/24 (victims), both `internal: true`.
   - router container on both networks with IP forwarding on, rp_filter disabled (spoofed sources must survive), tcpdump capturing there. This router is the "tap".
   - victims: nginx (web) and BIND9 (authoritative for a lab-only zone, recursion off).
   - benign generators: iperf3 profile, a scripted HTTP client (randomised think time, varied paths) and a scripted DNS client (popularity-weighted names).
   - attackers: hping3 SYN flood (with and without --rand-source), hping3 UDP flood (varied payload sizes and ports).
   - Ensure everything needed is installed at image build time (no runtime internet).
3. Scenario format (testbed/scenarios/*.yaml): seed, duration, benign profile, list of attacks with type, attacker container, parameters (rate, size, ports, source mode), start offset and duration. Write scenarios: benign_30min, syn_basic, syn_randsrc, syn_low_rate, udp_basic, udp_varied, mixed_syn_udp.
4. Orchestrator (testbed/orchestrator.py): starts a scenario, runs attacks on schedule, writes a ground-truth log (attack id, type, attacker IP, parameters, exact start/stop timestamps) and a manifest (scenario hash, seed, tool versions, image digests, git commit).
5. Forward-only capture: apply a BPF filter at the router so only client-net -> server-net packets are written (`src net 10.77.1.0/24 and dst net 10.77.2.0/24`). Spoofed sources are random, so also keep packets whose destination is in server-net regardless of source. Rotate pcaps (for example every 60 s) and record SHA-256 of each closed file in the manifest.
6. Flow and DNS extraction (testbed/extract/): a reference pcap-to-FlowEvent builder (dpkt or scapy) with configurable active/idle timeouts, and a DNS query extractor producing DnsEvent. Optionally also export NetFlow v9 with softflowd for the collector tests in Phase 2.
7. Labelling (testbed/label.py): label each flow/window from the ground-truth log only (match by attacker IP and time window, with a guard interval at attack boundaries marked "ignore" so boundary noise does not poison labels). Everything else is benign. Output Parquet: flows, dns, labels, plus manifest.yaml. Spoofed-source floods need a rule that labels by (destination, time window, attack id) because the source IPs are random.
8. Dataset checks (make lab-verify) that FAIL the build if violated:
   - zero packets in any pcap have a source inside server-net (forward-only property);
   - every attack window in the ground truth has labelled flows;
   - benign-only scenario has zero attack labels;
   - label counts and manifest hashes match the files.

ACCEPTANCE
`make lab SCENARIO=syn_basic` (and the other scenarios) runs from a clean checkout and `make lab-verify` passes. Report: size of each dataset, flows per label, and the exact commands you ran.

KNOWN PITFALLS (check each)
- A flood generated on the same host can saturate the VM; cap rates so the capture does not drop packets, and record tcpdump's drop counters in the manifest.
- Container clocks differ slightly from the orchestrator: take attack start/stop times from inside the attacker container or use a shared monotonic reference, and verify the timestamps against the pcap.
- Docker internal networks block published ports; capture and extraction must run inside the lab or on mounted volumes.
- Random-source SYN floods look like thousands of unique flows: make sure the flow builder bounds memory.

DO NOT
- Do not run attack tools outside the lab network.
- Do not commit pcaps; commit scripts and manifests, and put data under an ignored data/ directory (document how to regenerate or download).
~~~~

---

## Part 2: Phase 2 prompt (end-to-end skeleton)

~~~~text
# PHASE 2: End-to-end skeleton with one detector

GOAL
Replaying the syn_basic scenario produces a SYN-flood alert on a dashboard within 5 s of the detection window closing. This phase builds every pipeline stage once, thinly, so later phases only add detectors.

TASKS
1. Schemas (schemas/): JSON Schema or Protobuf for FlowEvent, DnsEvent, Alert; a validation helper; a version field.
2. Ingest:
   - pcap replay reader with a speed factor (1x, 10x, as-fast-as-possible) and exact timestamps preserved;
   - live capture on AF_PACKET (or libpcap) for an interface with no IP, behind a flag (tested manually or in a privileged container);
   - flow collector: receive-only UDP listener for NetFlow v5/v9 and IPFIX (use an existing parser library or goflow2; do not hand-roll v9 templates without tests). sFlow can come in Phase 7 if time is short; document it.
   - no outbound sockets anywhere in ingest/.
3. Normalizer: all sources become FlowEvent/DnsEvent, with direction_seen set honestly. Invalid or malformed input is counted and dropped, never crashes.
4. Message bus: Redpanda in Compose (single node for dev) with topics from CLAUDE.md, retention suitable for replay, and a thin producer/consumer wrapper with batching and back-pressure. Provide an in-memory bus implementation for unit tests.
5. Feature engine: windowing framework (tumbling 1 s and 10 s, sliding 60 s), keyed state with TTL eviction and a hard memory bound (evict and count when exceeded), event-time handling with a configurable lateness allowance.
6. Detector runtime: loads detectors from detectors/*/config.yaml, wires topics, batches inference, emits to alerts.raw. Implement the SYN-flood detector only:
   - features per (destination, 1 s window): SYN count, SYN-only ratio, unique sources, normalized source entropy, share of sources with no follow-up non-SYN packet within 5 s, TTL stddev, TCP options uniformity;
   - rule score from thresholds learned on benign data, plus an XGBoost or LightGBM classifier trained on the Phase 1 data, fused as max or a documented weighted combination; hysteresis and a minimum duration to avoid flapping.
7. Training pipeline (training/): dataset builder from Parquet, scenario-based split, training script, MLflow tracking, model artifact plus model card (training data hash, metrics, known failure modes).
8. Fusion (minimal): dedupe by (threat, entity, time bucket) and pass through to alerts.final.
9. Storage: ClickHouse tables for flows (sampled), features, alerts; migrations as code; a retention policy.
10. API (FastAPI): GET /alerts, GET /alerts/{id}, GET /health, GET /metrics (Prometheus). Authentication on every route except /health.
11. Dashboard: Grafana provisioned from files (datasource + dashboard JSON): alert feed, alerts per minute, throughput, pipeline lag.
12. Integration test: replay a small labelled pcap through the full stack (in Compose or testcontainers) and assert the expected alert appears with the right entity, and that benign-only replay produces none.

ACCEPTANCE
- `make demo-syn` replays syn_basic and the alert is visible in Grafana and via the API; measure and report alert latency (window close to alert visible) over 20 runs: median and p95.
- Benign-only replay: report false alerts per hour of replayed traffic.
- `make test` green, including the integration test.

PITFALLS
- Event time vs wall-clock time: replay at speed must use event time for windows or latency numbers are meaningless.
- Unbounded state under a random-source flood (one key per spoofed source) will exhaust memory: key by destination, keep per-source state in a bounded probabilistic structure (for example a counting sketch or capped LRU) and document the accuracy trade-off.
- Check the detector never reads response-direction fields; add a unit test asserting features are unchanged when reverse-direction packets are removed from a bidirectional capture.
~~~~

---

## Part 3: Phase 3 prompt (volumetric and slow attacks)

~~~~text
# PHASE 3: UDP flood and Slowloris, evaluation harness

GOAL
Two more detectors, a reusable training and evaluation harness, and the first honest per-threat metrics.

TASKS
1. Testbed additions: Slowloris attacker (script with configurable connection count, header interval, user-agent variation), UDP flood variants (payload sizes, destination ports, spoofed and real sources), benign UDP services to create hard negatives (DNS, NTP, a QUIC-like bulk transfer), benign slow clients (mobile-like long connections, large uploads). New scenarios: slowloris_100, slowloris_1000, slowloris_lowrate, udp_vs_benign_udp, mixed_all_so_far. Re-run lab-verify.
2. UDP flood detector, key = destination IP, 1 s: pps, bps, payload-length mean/variance, share of identical payload lengths, destination-port entropy, source-port entropy, unique sources, TTL spread, UDP share of traffic to that destination. Robust z-score of rate vs a rolling baseline (median and MAD), entropy rules, configurable allowlist, plus a GBDT classifier. Document why each feature separates flood from benign UDP.
3. Slowloris detector, key = (source, destination:80/443), 30 s sliding: concurrent open flows (no FIN/RST seen, age above threshold), share of flows under 1 KB over more than 30 s, median inter-packet interval and its regularity (coefficient of variation), mean packet length, flow-duration distribution; per-source aggregate across flows. Use flow shape only (traffic may be encrypted). Flow-level GBDT plus aggregate rule.
4. Evaluation harness (training/eval/): one command per detector that produces: precision, recall, F1, PR-AUC, detection delay (seconds from attack start to first alert), false positives per hour on benign-only data, confusion matrix, and a reliability diagram. Writes JSON plus a markdown report into docs/eval/.
5. Calibration: fit isotonic regression or Platt scaling on a held-out validation set; report expected calibration error before and after; store the calibrator with the model artifact.
6. Rule/ML fusion: document the combination, tune ONLY on the validation set, report both rules-only and hybrid numbers.
7. Cross-generator test: train SYN on hping3 data and evaluate on a second flood generator you implement yourself (for example a scapy-based SYN flood with different timing and options); same for UDP. Report the drop in recall honestly.
8. Update the pipeline test to replay mixed_all_so_far and assert each attack is detected with the correct label.

ACCEPTANCE
`make eval DETECTOR=udp_flood` and `make eval DETECTOR=slowloris` produce reports from a clean checkout. The report states split definitions (which scenarios are train, validation, test), and the test set was touched exactly once for the final numbers.

PITFALLS
- Slowloris and benign slow clients overlap: include hard negatives and report the confusion honestly.
- Time-split leakage: windows overlapping a train/test boundary must be dropped.
- If recall is near 1.0 and precision near 1.0 on the first run, suspect leakage (labels derived from features, or attack scenarios sharing a seed) and investigate before reporting.
~~~~

---

## Part 4: Phase 4 prompt (DNS and C2)

~~~~text
# PHASE 4: DNS tunnelling, DGA, C2 beaconing

GOAL
Detect the three remaining named threats from one-direction data, with a held-out-family test for DGA.

TASKS
1. DNS metadata path end to end: extractor (query side only), DnsEvent on events.dns, storage table. Document the flow-only fallback: when only flow records exist, use packets per second to port 53, query-size distribution and rate, and mark alerts "low visibility" with reduced confidence.
2. Testbed additions:
   - DNS tunnelling: dnscat2 and iodine clients against a lab-only authoritative zone, with varied record types, query rates and encodings; plus benign DNS with long names (CDN hostnames, DNSSEC-heavy domains, reverse lookups) as hard negatives.
   - DGA: implement at least four DGA families from published algorithm descriptions (for example dictionary-based, hash-with-date-seed, LCG-based, hex-string-based) as a generator script; clients query generated domains at realistic rates mixed with benign lookups. Benign corpus: a static Tranco top list file committed as data with its licence noted.
   - C2 beaconing: an emulator that beacons at configurable interval (5 s to 300 s), jitter (0 to 50 percent), payload size and size variance, over HTTP(S)-like traffic; benign periodic hard negatives (NTP, package-update checks, health checks, chat keep-alives).
   Scenarios for each plus a mixed_all scenario. Re-run lab-verify.
3. DNS tunnelling detector: per (client, parent domain) 60 s and per parent domain across clients. Features: unique subdomain count, mean and max qname length, maximum label length, subdomain character entropy, base32/base64-like character share, share of TXT/NULL/CNAME/MX queries, queries per minute, EDNS presence, unique-to-total ratio. GBDT with a rule override for extreme cases.
4. DGA detector: per registered domain, aggregated per client over 5 minutes. Features: length, entropy, digit ratio, longest consonant run, vowel ratio, n-gram log-likelihood under the benign corpus, dictionary-word coverage, TLD, new-domain rate per client. Lexical GBDT baseline; optionally a small character-level CNN. Do NOT use NXDOMAIN ratio. Train with family-held-out validation (leave one family out, repeat) and report per-family recall.
5. Beaconing detector: per (src, dst, dst port) with at least 20 events. Features: inter-arrival mean, standard deviation, coefficient of variation, MAD, autocorrelation peak, FFT or Lomb-Scargle peak ratio, payload-size coefficient of variation, duration, jitter-tolerant bucket score (share of intervals within a tolerance of the dominant interval). Benign periodic traffic: allowlist by configuration and learn a benign baseline; report the false positives it still produces.
6. Evaluate each with the Phase 3 harness; add a table to docs/eval/.
7. Correlation hook for Phase 5: emit entity keys (client IP, domain) so fusion can link DGA + beaconing on the same client.

ACCEPTANCE
All six named threats detected in the mixed_all replay; DGA evaluated on a held-out family with per-family recall reported; beaconing false positives on benign periodic traffic reported; every detector passes the "no response-direction features" unit test.

PITFALLS
- Tunnelling vs benign long names: tune on validation only, and keep the hard negatives in the test set.
- DGA models overfit to the generator's quirks: if held-out-family recall is far below in-family recall, say so and show it.
- Beaconing needs history: define behaviour for the first 20 events (no alert, or low-confidence) and test it.
~~~~

---

## Part 5: Phase 5 prompt (intelligence layer and one-way proof)

~~~~text
# PHASE 5: Anomaly detection, fusion, evidence, one-way enforcement

GOAL
Turn detections into intelligence (calibrated, explained, correlated), cover unknown threats, and make the one-way property enforceable and provable.

TASKS
1. Anomaly detector: isolation forest or autoencoder per entity class trained on a benign baseline window; emits "unclassified anomaly" alerts with confidence capped below labelled detections. Evaluate it on attack types held out of training (it should flag at least some of them) and on benign-only data (false positives per hour).
2. Fusion (fusion/): dedupe by (threat, entity, time bucket); correlation rules, configurable in YAML, for example DGA + beaconing on one client -> "probable C2 infection" incident, many Slowloris sources vs one destination -> "distributed slow attack"; alert lifecycle (new, updated, closed after quiet period); severity = f(confidence, volume, duration, target criticality from a static asset list in config).
3. Evidence: for every alert store top-5 SHAP feature contributions, a time series of the key metric around the window, 5 to 10 representative flows or domains, and which rules fired. Verify SHAP values sum plausibly to the model output for a sample and test it.
4. Alert detail UI: if Grafana cannot show it well, build a small React alert-detail page (timeline with the detection window highlighted, SHAP bar chart, sample flows, rule hits, raw JSON). Keep it read-only and authenticated.
5. Dashboard extras: entity view (history per IP or domain across threats), per-threat pages with feature time series and current thresholds, pipeline view (queue lag, dropped events, model versions).
6. One-way enforcement:
   - capture interface configured with no IP/ARP, receive-only (document the exact commands);
   - analytics containers on `internal: true` networks with no default route;
   - nftables rules dropping all egress from the ingest namespace (ship as deploy/nftables.conf and apply in the lab);
   - a CI lint (AST or grep based) that FAILS if ingest/ or detectors/ import or call anything for outbound connections (socket.connect, requests, urllib, httpx, aiohttp, dns resolution, subprocess calls to curl/wget/ping);
   - `make prove-oneway`: starts the stack, tries from the ingest namespace to (a) send a TCP/UDP packet to the victim network, (b) send a DNS query, (c) ping, and asserts all fail; asserts the mirror interface's TX packet counter stayed at zero; prints a one-line PASS/FAIL.
   - dashboard panel "One-way status" showing the last result of the proof test.

ACCEPTANCE
- `make prove-oneway` passes, and you demonstrate it FAILS when you deliberately add a route or remove the nftables rule (show both runs).
- Every alert in the mixed_all replay has evidence visible in the UI.
- Correlated incident appears for a client running DGA + beaconing together.

PITFALLS
- A proof test that cannot fail is worthless: include the negative control above.
- Correlation can double-count: test that one incident does not also create duplicate alerts.
- Do not let fusion state grow without bound; test with a long replay.
~~~~

---

## Part 6: Phase 6 prompt (blockchain integration)

~~~~text
# PHASE 6: Blockchain integration

CONTEXT
./sih-chain (copy into this repo as chain/ and anchor/, keep its tests) contains: EvidenceAnchor.sol (per-sensor sequence numbers, Merkle roots, prevRoot links), ModelRegistry.sol (N-of-M approval, revocation), the Python anchor service (RFC 8785 canonical hashing, content-addressed evidence store, SQLite hash-chained log, Merkle batching, retry, crash recovery), verification API, CLI, and a 4-validator Besu QBFT Compose setup. Its 40 pytest tests pass against py-evm. The Besu network, scripts/gen-network.sh and the Compose file were NEVER run: expect to fix them.

GOAL
Fusion output is anchored on a real private chain, detectors load only approved models, the dashboard can verify any alert, and the system survives validator and ledger failures without losing or delaying alerts.

TASKS
1. Import sih-chain, make `make test` run both suites, confirm 40/40 still pass in the new location.
2. Bring up the Besu network: run scripts/gen-network.sh, then Compose. Fix whatever is broken (image tag, flags, genesis fields such as zeroBaseFee, extraData, bootnode enode, permissions, healthchecks). Verify with an RPC call that block production works with 4 validators and ~2 s blocks. Record the commands and outputs.
3. Deploy contracts with `sihchain deploy` using throwaway dev keys (never commit them), grant roles (sensor, publisher, approvers with threshold 2), write addresses.json to a volume.
4. Integrate the anchor service: consume alerts.final (add a Redpanda consumer adapter next to the existing JSON-lines reader), write evidence bundles to MinIO or the file store behind the EvidenceStore interface (implement an S3/MinIO adapter if you use MinIO and test it), anchor batches every 10 s or 100 alerts. Keep the service a separate process: it must never block the detection consumers.
5. Model gate: at detector startup call require_approved() for each artifact; register and approve the Phase 2 to 5 models through a documented script (publisher key registers, two approver keys approve). A detector must refuse an unapproved or revoked artifact and report it clearly.
6. API and dashboard: expose the integrity API through the main API; add an Integrity panel (chain height, validator status, last anchored batch, anchor lag, sequence-gap and log_truncated checks), a per-alert badge (pending, anchored with block number, failed), a Verify button that runs the same steps as `sihchain verify` and shows each step, and a model registry view (hash, dataset hash, approvals, revoked).
7. Sensitive data: confirm only hashes and metadata reach the chain. If any bundle hash could expose low-entropy values on its own, switch to keyed hashing and document it.
8. Chaos tests (scripted, repeatable, in make chaos): stop 1 validator -> anchoring continues; stop 2 -> anchoring stops, detection latency unchanged, local log keeps growing, backlog drains after restart; stop all nodes; kill the anchor service between submit and mark and verify recovery. Measure detection latency during each failure vs normal.
9. Tamper tests (scripted): edit an alert row in ClickHouse, change one byte of a stored evidence bundle, delete a log entry, truncate the log tail; each must be detected by Verify or the status checks, while the ledger root is unchanged. Record what is NOT detectable (for example deleting unanchored newest entries) in docs.
10. Security: run Slither on the contracts and fix or justify every finding; add a short threat model (sensor key compromise, validator collusion, evidence store compromise, key rotation procedure); keep keys out of images and git.
11. Reconcile docs: make section 14 of the design doc match what is actually built.

ACCEPTANCE (show each with commands and output)
- Network up, 4 validators, blocks produced, contracts deployed.
- End-to-end: replay mixed_all, every alert reaches "anchored" within a measured p95 latency; Verify passes for a sample of 50 alerts.
- Tamper demo works (edit, Verify fails, ledger root unchanged).
- Unapproved model file refused; revoked model refused.
- Chaos results table as above.
- Slither report with findings dispositioned.

PITFALLS
- Besu private-chain flags differ between versions: check the docs for the exact version you pin.
- Do not put the chain on the detection critical path or let an outage grow memory: confirm the backlog is bounded and spills to the durable log.
- py-evm tests do not prove QBFT behaviour: say which claims rest on the real network.
~~~~

---

## Part 7: Phase 7 prompt (hardening, evaluation, release)

~~~~text
# PHASE 7: Hardening, full evaluation, release

GOAL
A reproducible, documented v0.1.0 with honest numbers and a one-command demo.

TASKS
1. Load test: replay scaled traffic and measure flow records per second, CPU, memory, bus lag and end-to-end latency percentiles; find the first bottleneck by profiling, fix the biggest one, re-measure. Report before and after. If you move a hot path to Rust or Go, justify it with the profile.
2. Robustness tests: packet loss of 1, 5 and 10 percent; sFlow-style 1-in-N sampling (implement the sFlow collector if it was deferred); timestamp jitter; flow-only vs packets-plus-DNS visibility. Report metric degradation per detector.
3. Ablations: rules only, ML only, hybrid; with and without the anomaly detector; with and without calibration.
4. Final evaluation on the untouched test scenarios, once: per-threat precision, recall, F1, PR-AUC, detection delay, false positives per hour on benign-only replays; confusion matrices; calibration plots; cross-generator results; DGA held-out-family table; system metrics; anchor latency and verification time. Generate docs/eval/REPORT.md automatically from a script.
5. Documentation: README quickstart (5 minutes), architecture, runbook (start, stop, rotate keys, add a detector, restore after failure), evaluation report with limitations, threat model, model cards for every model, "how to add a detector", CONTRIBUTING, CODE_OF_CONDUCT, issue templates, roadmap.
6. Packaging: `docker compose up` starts everything on a fresh machine (no manual steps beyond copying an env example); pinned image digests; SBOM generation in CI; dependency vulnerability scan; release workflow that tags v0.1.0 and attaches the evaluation report.
7. Demo kit: scripts/demo.sh runs the scripted scenario (benign traffic, each attack, alerts with evidence, correlated incident, tamper demo, unapproved-model refusal, one-way proof, with a pause between steps); a pre-recorded fallback (screen recording instructions plus a replay pcap); a 5-minute pitch outline with timings.
8. Clean-machine test: clone into a fresh VM or container, follow only the README, and fix every step that fails.

ACCEPTANCE
Fresh-clone `docker compose up` reproduces the demo; `make test`, `make eval-all`, `make prove-oneway`, `make chaos` all pass; docs/eval/REPORT.md exists and every number in it is generated by a script in the repo.

FINAL REPORT
List what is verified, what is unverified and why, known limitations (lab data is cleaner than real traffic; calibration may not transfer; one-direction visibility limits some features), and open questions for the organisers.
~~~~

---

## Appendix A: Report template (the agent must end every phase with this)

~~~~text
PHASE <n> REPORT
Summary: <3 sentences>

Verified (command -> relevant output, trimmed):
- <item> -> <command> -> <output>

Done but unverified (reason):
- <item>: <why it could not be run>

Not done:
- <item>: <why>

Metrics (generated by script, path to the script and output file):
- <table>

Assumptions made (one line each):
- <assumption>

Risks and surprises:
- <anything unexpected, including any result that looked too good>

Next phase blockers:
- <none | decisions needed from me>
~~~~

## Appendix B: Your review checklist (human)

After every phase, check:

1. You ran the acceptance command yourself and got the same result.
2. The split definitions are written down and the test set was used once.
3. A suspiciously good metric has an explanation, or the agent investigated it.
4. No test was deleted, skipped or weakened (look at the diff of `tests/`).
5. No outbound network code appeared in `ingest/` or `detectors/`.
6. No secrets, pcaps or large files were committed.
7. The report separates verified from unverified honestly.
8. The repo still runs from a clean checkout.

## Appendix C: When the agent must stop and ask you

- A change that would send anything out of the ingest path, or require inbound access to the enclave.
- Outbound export from the enclave (public anchoring): needs the organisers' answer first.
- A threat list change or new threat from the organisers.
- Using real (non-lab) traffic or third-party datasets whose licence is unclear.
- Replacing the chosen blockchain platform or the bus/storage stack.
- A requirement that cannot be met with the available hardware (for example sustained throughput targets).
