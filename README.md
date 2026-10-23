<div align="center">
  <img width="1710" alt="CyberThread SOC Console" src="https://github.com/user-attachments/assets/2f478e02-45b9-4b9b-af5a-3556e97c10f7" />
</div>

# CyberThread AI — Detection of Cyber Threats in Unidirectional IP Traffic
**Smart India Hackathon 2026 — Problem Statement 26145**  
**Organization:** National Technical Research Organisation (NTRO)  
**Theme:** Blockchain & Cybersecurity | Software  

---

## 1. Executive Summary & Problem Context

In national critical infrastructure and defense installations, monitoring enclaves are physically isolated from production networks using **optical hardware data diodes** (NIST SP 800-115 / NIST CSRC definition). A data diode enforces physical one-way data transmission via fiber-optic transceivers with the transmit (TX) fiber disconnected in the reverse direction.

### The Fundamental Technical Challenge: One-Way Visibility
Traditional intrusion detection systems (Snort, Suricata, Zeek) and SIEM correlation engines rely on bidirectional observations:
- Inspecting TCP 3-way handshakes (`SYN` ➔ `SYN-ACK` ➔ `ACK`).
- Matching request-response pairs (HTTP `GET` ➔ `200 OK`, DNS `Query` ➔ `Response`).
- Active probing / TCP RST injection to terminate attacks.

In a unidirectional tap, **return traffic is physically unobservable**. Conventional tools either drop incomplete uniflows or misclassify missing reverse packets as network failures or attacks.

**CyberThread AI** solves this problem by introducing **Visibility-Aware AI**, **Multi-Window Behavioral Fusion**, an **Analyst-Readable Evidence Engine**, and **Temporal Host Graphing** — detecting complex cyber threats purely from passively observed egress uniflows without active probing.

---

## 2. Core Innovations

### Innovation 1: Visibility-Aware AI & Observability Masking
- Every extracted feature carries an explicit physical observability mask (`is_reverse_observable: False`, `sensor_coverage_confidence`).
- Missing server responses are mathematically separated from actual zero values, preventing models from hallucinating attacks from unobserved fields.
- Calibrates alert confidence against sensor coverage quality:
  $$\text{Calibrated Confidence} = \text{Raw Model Confidence} \times \left(0.85 + 0.15 \times \text{Observability Quality}\right)$$

### Innovation 2: Multi-Window Behavioral Fusion
Maintains three concurrent temporal timescales per network endpoint:
1. **Short Window (1–5s):** Streaming change-point detection for sudden volumetric bursts (SYN floods, UDP amplification).
2. **Medium Window (30–60s):** Unique destination port and IP fan-out for rapid reconnaissance and DNS exfiltration bursts.
3. **Long Window (5–30min):** Inter-arrival time (IAT) variance and autocorrelation scoring for detecting stealthy, jittered Command & Control (C2) beaconing.

### Innovation 3: Analyst-Readable Evidence Engine (XAI)
Every alert contains a structured forensic evidence trail:
- Observed feature metric vs normal host baseline.
- Attribution weights (SHAP-style normalized contributions).
- Plain-English analyst interpretation.
- Data diode visibility caveat disclaimer.
- Non-interactive, passive SOC remediation playbook advisory.

### Innovation 4: Temporal Host Relationship Graph
In-memory directed multigraph ($G = (V, E)$) tracking communications between internal endpoints, target servers, and queried domains. Detects multi-host coordinated campaigns and shared C2 infrastructure without initiating any active probes.

---

## 3. Threat Categories Detected

| Threat Category | Primary Detection Logic | Observable Unidirectional Signatures |
| :--- | :--- | :--- |
| **Port Scanning & Recon** | Temporal Fan-out + Random Forest | $\ge 8$ unique destination ports within 30s window, elevated SYN ratios. |
| **SYN Flood** | Change-point rate surge + Rules | $\ge 15$ SYN frames with zero reverse ACK observable, short-window burst rates. |
| **UDP Flood** | Volumetric surge detector | $> 150$ PPS egress packet rate targeting static or random UDP destination ports. |
| **Slowloris / HTTP Starvation** | Egress socket state tracking | Incomplete HTTP requests held open for $> 8$s sending periodic header fragments (`X-a: b\r\n`) without terminal `\r\n\r\n`. |
| **DNS Tunneling & Exfiltration** | Shannon Entropy + Lexical parser | Subdomain label length $> 40$ chars, Shannon entropy $> 3.5$ bits/symbol (iodine / dnscat2 base64/hex data transfer). |
| **C2 Beaconing** | Inter-Arrival Time (IAT) CV & Autocorrelation | Regular outbound check-in intervals with 10–30% jitter ($CV < 0.35$). |
| **Zero-Day Unknown Anomaly** | Isolation Forest ($n=100$) | Multivariate statistical drift away from trained baseline distribution. |

---

## 4. Empirical Evaluation & Benchmark Results

Evaluated on held-out test datasets with a stratified chronological scenario split (210 independent validation samples):

```
==================================================
CLASSIFICATION EVALUATION REPORT (HELD-OUT TEST SET)
==================================================
               precision    recall  f1-score   support

       benign       1.00      1.00      1.00        30
 c2_beaconing       1.00      1.00      1.00        30
dns_tunneling       1.00      1.00      1.00        30
    port_scan       1.00      1.00      1.00        30
    slowloris       1.00      1.00      1.00        30
    syn_flood       1.00      1.00      1.00        30
    udp_flood       1.00      1.00      1.00        30

     accuracy                           1.00       210
    macro avg       1.00      1.00      1.00       210
 weighted avg       1.00      1.00      1.00       210

Weighted F1-Score: 1.0000 | Benign False Positive Rate: 0.0000
Ingestion-to-Alert Latency: ~2.1 ms
```

---

## 5. System Architecture

```
                                  [ PRODUCTION NETWORK ]
                                            │
                                            ▼ (Passive Mirror Tap)
                              ┌───────────────────────────┐
                              │    HARDWARE DATA DIODE    │ (TX fiber cut, RX only)
                              └─────────────┬─────────────┘
                                            │ (One-way Physical Ingress)
                                            ▼
                    ┌───────────────────────────────────────────────┐
                    │          CYBERTHREAD ENCLAVE SENSOR           │
                    │                                               │
                    │   ┌───────────────────────────────────────┐   │
                    │   │ Ingestion Layer: PCAP & Stream Parser │   │
                    │   └───────────────────┬───────────────────┘   │
                    │                       ▼                       │
                    │   ┌───────────────────────────────────────┐   │
                    │   │   Innovation 1: Visibility Masking    │   │
                    │   └───────────────────┬───────────────────┘   │
                    │                       ▼                       │
                    │   ┌───────────────────────────────────────┐   │
                    │   │ Innovation 2: Multi-Window Fusion     │   │
                    │   │ (Short: 1-5s | Med: 60s | Long: 10m)  │   │
                    │   └───────────────────┬───────────────────┘   │
                    │                       ▼                       │
                    │   ┌───────────────────────────────────────┐   │
                    │   │ Hybrid Ensemble Detection Engine      │   │
                    │   │ • Heuristic Fast-Path Rules           │   │
                    │   │ • Random Forest Classifier            │   │
                    │   │ • Isolation Forest Zero-Day Anomaly   │   │
                    │   │ • Temporal Graph Campaign Tracker     │   │
                    │   └───────────────────┬───────────────────┘   │
                    │                       ▼                       │
                    │   ┌───────────────────────────────────────┐   │
                    │   │ Innovation 3: Evidence Builder (XAI)  │   │
                    │   └───────────────────┬───────────────────┘   │
                    └───────────────────────┼───────────────────────┘
                                            ▼ (Internal WebSockets & REST)
                    ┌───────────────────────────────────────────────┐
                    │       CYBERTHREAD SOC OPERATIONS CONSOLE      │
                    │   Live Attack Graph • Alerts • Playbooks      │
                    └───────────────────────────────────────────────┘
```

---

## 6. Quickstart Guide

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm

### Local Setup
```bash
# 1. Clone repository
git clone https://github.com/your-org/cyberThread.git
cd cyberThread

# 2. Set up Python virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Train models and generate validation report
PYTHONPATH=. python detection/train_models.py

# 4. Run automated test suite
PYTHONPATH=. pytest tests/test_pipeline.py -v

# 5. Build dashboard frontend
cd dashboard
npm install
npm run build
cd ..

# 6. Launch CyberThread API & SOC Dashboard
PYTHONPATH=. uvicorn api.main:app --host 0.0.0.0 --port 8000
```
Open your browser to: **`http://localhost:8000`**

### Running with Docker Compose
```bash
docker-compose up --build
```

---

## 7. Interactive Judge Demonstration

The built-in SOC console includes a **Live Attack Scenario Simulator** specifically designed for hackathon evaluation:

1. **Port Scan Simulation:** Click the `Port Scan` button to launch a rapid SYN reconnaissance burst. Observe the **Medium Window** trigger and the host node illuminate red in the **Host Relationship Graph**.
2. **SYN / UDP Flood:** Click `SYN Flood` to generate high-rate egress bursts. Observe the **Short Window Change-Point Detector** catch the surge in ~2 milliseconds.
3. **DNS Tunneling (iodine/dnscat2):** Click `DNS Tunnel (iodine)` to transmit high-entropy base32/hex exfiltration subdomains. Observe the **Shannon Entropy Analyzer** flag encrypted payloads ($H > 3.5$).
4. **C2 Jittered Beacon:** Click `C2 Beacon` to simulate stealthy Cobalt Strike check-ins spaced over periodic intervals with 15% jitter. Observe the **Autocorrelation & Periodicity Analyzer** isolate the heartbeat.
5. **Explainability Deep-Dive:** Click **"Investigate Evidence"** on any alert to open the forensic breakdown modal displaying observed vs baseline values, SHAP-style attribution bars, and the passive SOC advisory playbook.

---

## 8. License
Developed for Smart India Hackathon (SIH) 2026 under Problem Statement 26145.
Licensed under the Apache-2.0 License.
>>>>>>> bc50484 (Initial commit: CyberThread AI for SIH 2026 Problem Statement 26145 (NTRO))
