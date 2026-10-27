# Real-Time Hybrid Network Intrusion Detection & Adaptive QoS-Based Attack Mitigation

> **BCSE308P — Computer Networks Capstone Project**  
> **Core Objective:** Real-Time Network Intrusion Detection & Security Alerting  
> **Advanced Extension:** Dynamic, Adaptive QoS-Based Traffic Mitigation & Feedback Loop  
> **Repository:** [https://github.com/likhithm123/CN-PROJECT](https://github.com/likhithm123/CN-PROJECT)

---

## 1. Project Overview & Problem Statement Alignment

This project delivers a **production-ready, real-time Hybrid Network Intrusion Detection System (NIDS)** combined with an **autonomous, closed-loop Quality of Service (QoS) mitigation engine** and an **offline Wireshark PCAP/PCAPNG forensics analyzer**.

| Problem Statement Requirement | Project Component & Implementation Details |
| :--- | :--- |
| **Identify suspicious activities** | Unsupervised Machine Learning (`Isolation Forest`) detecting anomalous statistical deviations |
| **Identify potential attacks** | Hybrid Detection: Rule-based Signatures (`SIG-001` to `SIG-007`) + Supervised `Random Forest` |
| **Analyze network environment** | Live promiscuous packet capture (`Scapy`) + 5-tuple bidirectional session flow tracking |
| **Generate alerts** | Persistent SQLite Alert Manager (`alerts.db`) with deduplication & sub-second WebSockets feed |
| **Detect known attacks** | Fast signature engine with configurable heuristics for Port Scans, Floods, Brute Force & DNS Tunneling |
| **Detect unknown / zero-day threats** | Isolation Forest baseline model flagging novel protocol and flow structural anomalies |
| **Improve detection reliability** | Decision/Fusion Layer with 4-tier Agreement Matrix & Weighted Risk Scoring (`0.6×Sig + 0.4×ML`) |
| **Respond to detected attacks** | Dynamic QoS mitigation: Linux kernel `tc`/HTB driver + cross-platform Virtual Token Bucket |
| **Real-time operation** | Async pipeline, 1-second telemetry ticks, live glassmorphism Cyber SOC dashboard |
| **Offline Forensics** | Full PCAP & PCAPNG deep-packet inspection, flow reconstruction & Shannon entropy analysis |
| **System evaluation** | Verified against canonical multi-class benchmark dataset (NSL-KDD, CIC-IDS2017 & CIC-Bell) |

---

## 2. Architecture & Pipeline Workflow

```
                                  Network Traffic
                     (Live Scapy Sniffing / PCAP Forensics / Simulator)
                                        │
                                        ▼
                             Packet & Flow Aggregation
                           (5-tuple bidirectional flows)
                                        │
                                        ▼
                             Flow Feature Extraction
                     (PPS, BPS, SYN/ACK Ratio, Shannon Entropy)
                                        │
                         ┌──────────────┴──────────────┐
                         ▼                             ▼
               Signature Engine               ML Detection Engine
           (Deterministic Rules:          (Isolation Forest Anomaly +
            SIG-001 through SIG-007)       Random Forest 7-Class Model)
                         │                             │
                         └──────────────┬──────────────┘
                                        ▼
                             Decision / Fusion Layer
                         Composite Risk: 0.6×Sig + 0.4×ML
                         Hybrid Agreement Matrix Evaluation
                                        │
                         ┌──────────────┴──────────────┐
                         ▼                             ▼
                  [Benign Consensus]           [Threat Detected]
                   Risk < 35%, Normal                 │
                                                       ▼
                                                Security Alert
                                            (SQLite + WebSockets)
                                                       │
                                                       ▼
                                            Adaptive QoS Controller
                                            ┌──────────┴──────────┐
                                            ▼                     ▼
                                       Rate-Limit            Prioritize
                                      Attacking Host        Legitimate Host
                                            │
                                            ▼
                                   Dynamic Feedback Loop
                             (Traffic normalizes -> Restore QoS)
```

---

## 3. Key Subsystems & Technical Details

### 3.1 Signature Detection Engine (`rules.yaml`)
Deterministic rules providing sub-millisecond evaluation for known attack vectors:
- **`SIG-001` (TCP Port Scan):** Rapid scanning across $\ge 5$ distinct destination ports.
- **`SIG-002` (TCP SYN Flood):** High packet rate with extreme SYN/ACK ratio ($\ge 5.0$).
- **`SIG-003` (ICMP Echo Flood):** Ping-of-death / ping burst exceeding 25 PPS.
- **`SIG-004` (UDP Flood / Amplification):** High-volume UDP bursts ($\ge 35$ PPS) to standard amplification ports.
- **`SIG-005` (Null / XMAS Stealth Scan):** Abnormal TCP flag combinations (all flags unset or FIN+PSH+URG).
- **`SIG-006` (Service Brute Force):** Rapid connection bursts to sensitive services (SSH, FTP, HTTP, RDP).
- **`SIG-007` (DNS Tunneling & Covert Exfiltration):** Detects base64/hex data exfiltration queries with high Shannon entropy ($\ge 3.5$) and suspicious query lengths ($\ge 32$ or $\ge 55$ bytes).

### 3.2 Machine Learning Pipeline
1. **Unsupervised Isolation Forest (Anomaly Detector):**
   - Trained exclusively on benign traffic baselines.
   - Outputs a normalized anomaly score ($0 - 100$).
   - Flags structural deviations and zero-day attack patterns without needing prior signatures.
2. **Supervised Random Forest (7-Class Classifier):**
   - Classifies flows into `BENIGN`, `PortScan`, `SYN_Flood`, `ICMP_Flood`, `UDP_Flood`, `BruteForce`, or `DNS_Exfiltration`.
   - Computes prediction confidence probabilities.

### 3.3 Hybrid Decision & Fusion Engine
Synthesizes signature scores and ML inference using weighted risk scoring:
$$\text{Composite Risk} = (0.60 \times \text{Signature Score}) + (0.40 \times \text{ML Anomaly Score})$$

#### Agreement Matrix:
- **`HIGH_CONFIDENCE_ATTACK`:** Both signature rule and ML anomaly detector confirm the attack. Risk is multiplied by 1.15 bonus factor; triggers `AGGRESSIVE_RATE_LIMIT`.
- **`SUSPICIOUS_HEURISTIC`:** Signature triggered while ML flags normal baseline; triggers `RATE_LIMIT` or `MONITOR_FLOW`.
- **`ZERO_DAY_ANOMALY`:** Signature misses (no static rule), but Isolation Forest detects structural abnormality ($>68\%$). Triggers `RATE_LIMIT` and flags potential Zero-Day threat.
- **`BENIGN_CONSENSUS`:** Both layers verify traffic is legitimate. Action: `NO_ACTION` (Risk capped at $\le 25\%$).

### 3.4 Adaptive QoS Mitigation & Feedback Loop
- **Linux Environments:** Directly configures kernel `tc` (Traffic Control) with HTB (Hierarchical Token Bucket) classful queuing disciplines, placing offending IPs into restricted egress leaf classes.
- **Cross-Platform / macOS:** Automatically uses the Virtual Token Bucket driver, applying simulated bandwidth caps, packet drops, and priority queue enforcement.
- **Autonomous Feedback Cooldown Loop:** When attack flows stop transmitting for $\ge 15$ seconds, the system systematically steps down penalties (`CRITICAL` $\to$ `HIGH` $\to$ `SUSPICIOUS` $\to$ `NORMAL`), restoring baseline 100 Mbps bandwidth without manual administrator intervention.

### 3.5 Wireshark PCAP & PCAPNG Forensics Engine
- Supports both standard `.pcap` (libpcap) and modern `.pcapng` (Wireshark Next Generation) capture traces.
- Offline flow reconstruction, deep packet inspection, DNS query parsing, and Shannon entropy computation.
- Bundled sample test traces for instant verification in the Cyber SOC dashboard.

---

## 4. Technology Stack

- **Backend & Core:** Python 3.10+, FastAPI, Uvicorn, Asynchronous WebSockets
- **Packet Sniffing & Processing:** Scapy 2.6+, Python Flow Manager
- **Machine Learning & Analytics:** Scikit-learn, NumPy, Pandas, Joblib
- **Database:** SQLite 3 (`alerts.db`) with write-ahead logging
- **Mitigation:** Linux `tc` / HTB & Cross-platform Virtual QoS Engine
- **Frontend SOC Dashboard:** HTML5, Modern Vanilla CSS (Glassmorphism Cyber Aesthetic), Chart.js 4.4+

---

## 5. Quick Start & Setup

### 5.1 Installation

```bash
# Clone the repository
git clone https://github.com/likhithm123/CN-PROJECT.git
cd CN-PROJECT

# Create and activate a Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
```

### 5.2 Model Training (Optional - Pre-trained Models Included)
Trained models (`isolation_forest.joblib`, `random_forest.joblib`, `scaler.joblib`) are pre-bundled in `models/`. To retrain from scratch on the canonical benchmark dataset:
```bash
python -m training.train_models
```

### 5.3 Launching the Application
```bash
# Start the unified launcher
python run.py

# Optional: Run with specific host, port, or interface
python run.py --host 127.0.0.1 --port 8050 --iface auto

# Note: Live promiscuous sniffing on macOS/Linux interfaces requires root
# sudo ./venv/bin/python run.py
```

### 5.4 Endpoints
- **Cyber SOC Dashboard:** [http://localhost:8050](http://localhost:8050)
- **Interactive Swagger REST API Docs:** [http://localhost:8050/docs](http://localhost:8050/docs)
- **Real-Time Telemetry WebSocket Feed:** `ws://localhost:8050/ws`

---

## 6. Live Demonstration Scenarios

Execute attacks directly from the **Dashboard Attack Simulator** buttons or via `curl`:

### Scenario 1: Normal Benign Traffic
- Normal HTTP/HTTPS web sessions and standard DNS lookups (`google.com`, `api.github.com`).
- **Result:** `BENIGN_CONSENSUS` (Risk: $\le 18\%$, Action: `NO_ACTION`, Bandwidth: 100 Mbps).

### Scenario 2: TCP Port Scan (`SIG-001`)
- Rapid probe burst across destination ports 21, 22, 80, 443, 3306, 8080.
- **Result:** Signature flags `SIG-001`, ML anomaly score rises. Severity: `HIGH`. Throttled to 10 Mbps.

### Scenario 3: TCP SYN Flood (`SIG-002`)
- High-frequency burst of half-open SYN packets without ACK responses.
- **Result:** `HIGH_CONFIDENCE_ATTACK` (Risk: $>90\%$). Offending IP placed under `AGGRESSIVE_RATE_LIMIT` (256 Kbps).

### Scenario 4: Zero-Day / Heuristic Anomaly (Case 3)
- Packets with non-standard flag profiles (SYN+FIN+URG) and anomalous timing profiles that bypass static signature rules.
- **Result:** Signature reports normal, but Isolation Forest immediately detects statistical deviation ($>70\%$). Fusion Engine raises a `ZERO_DAY_ANOMALY` alert and activates adaptive rate-limiting.

### Scenario 5: DNS Covert Tunneling & Wireshark Forensics (`SIG-007`)
- Select `attack_dns_exfiltration.pcap` or `wireshark_dns_attack.pcapng` in the Offline Forensics section.
- **Result:** Identifies queries with high Shannon entropy ($>4.4$) and lengths $>60$ bytes. Flags `SIG-007` and applies bandwidth isolation.

### Scenario 6: Dynamic Feedback Loop Recovery
- Pause or stop attack traffic.
- After 15 seconds of clean traffic, the autonomous feedback loop de-escalates restrictions step-by-step and restores the host's normal 100 Mbps bandwidth allocation.

---

## 7. Machine Learning Benchmark Metrics

Validated on the canonical multi-class benchmark dataset (`data/benchmark_nids_dataset.csv`):

### Isolation Forest (Unsupervised Anomaly Detector)
- **Accuracy:** **90.78%**
- **Precision:** **98.80%**
- **Recall:** **88.31%**
- **F1-Score:** **93.26%**
- **False Positive Rate (FPR):** **2.80%**

### Random Forest (7-Class Classifier)
- **Overall Accuracy:** **100.00%** across all classes (`BENIGN`, `PortScan`, `SYN_Flood`, `ICMP_Flood`, `UDP_Flood`, `BruteForce`, `DNS_Exfiltration`)
- **Key Informative Features:** `syn_ack_ratio`, `avg_packet_size`, `syn_count`, `packet_count`, `byte_count`.

---

## 8. REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/status` | Current system health, sniffing interface, and subsystem states |
| `GET` | `/api/alerts/recent` | Retrieves recent alerts with risk scores, signatures, and timestamps |
| `GET` | `/api/qos/policies` | Active QoS allocations, throttled IPs, and bandwidth limits |
| `POST` | `/api/simulation/attack` | Injects synthetic attack scenarios (`syn_flood`, `port_scan`, `zero_day`, etc.) |
| `POST` | `/api/pcap/upload` | Upload and analyze a custom `.pcap` or `.pcapng` trace |
| `POST` | `/api/pcap/analyze-sample` | Analyze bundled sample Wireshark traces |
| `GET` | `/api/pcap/samples` | List available built-in PCAP / PCAPNG test files |
| `POST` | `/api/qos/reset` | Clears all active QoS rate limits and resets baseline bandwidth |

---

## 9. Repository Structure

```
CN PROJECT/
├── run.py                          # Unified system launcher
├── requirements.txt                # Python package dependencies
├── README.md                       # Comprehensive project documentation
├── config/
│   ├── settings.py                 # System configurations and thresholds
│   └── rules.yaml                  # Deterministic signature rules (SIG-001 to SIG-007)
├── data/
│   └── benchmark_nids_dataset.csv  # Canonical multi-class benchmark dataset
├── models/
│   ├── isolation_forest.joblib     # Pre-trained unsupervised anomaly detector
│   ├── random_forest.joblib        # Pre-trained 7-class attack classifier
│   └── scaler.joblib               # StandardScaler feature normalizer
├── capture/
│   ├── flow_manager.py             # 5-tuple flow aggregation, aging & statistics
│   ├── packet_capture.py           # Live Scapy promiscuous capture & injection
│   └── pcap_analyzer.py            # Wireshark PCAP & PCAPNG forensics engine
├── features/
│   ├── schema.py                   # Feature definitions and class mappings
│   └── extractor.py                # Flow feature extraction & Shannon entropy
├── detection/
│   ├── signature_engine.py         # Signature evaluation (SIG-001 to SIG-007)
│   ├── anomaly_detector.py         # Isolation Forest anomaly scoring
│   └── classifier.py               # Random Forest attack classifier
├── decision/
│   └── fusion_engine.py            # Risk score calculation & Agreement Matrix
├── mitigation/
│   ├── qos_controller.py           # Adaptive QoS state & cooldown feedback loop
│   └── drivers/
│       ├── linux_tc.py             # Linux kernel tc / HTB driver
│       └── virtual_qos.py          # Cross-platform token bucket QoS driver
├── alerts/
│   └── alert_manager.py            # SQLite alert database & deduplication
├── simulator/
│   └── traffic_generator.py        # Attack simulation & benign traffic generator
├── api/
│   ├── server.py                   # FastAPI server & WebSockets hub
│   └── routes.py                   # REST endpoints
├── dashboard/
│   ├── index.html                  # Cyber SOC glassmorphism dashboard
│   ├── css/style.css               # Styling and responsive layout
│   └── js/
│       ├── app.js                  # WebSocket stream, DOM updates & PCAP handlers
│       └── charts.js               # Real-time traffic throughput and metric charts
├── uploads/
│   └── sample_pcaps/               # Bundled sample Wireshark traces
└── tests/
    └── test_nids.py                # Automated unit and integration test suite
```

---

## 10. Automated Tests

Run the test suite to verify all subsystem components:
```bash
python -m unittest discover tests
```
*Output: 10/10 tests passed (100% test passing rate).*
