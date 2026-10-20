# Real-Time Hybrid Network Intrusion Detection and Adaptive QoS-Based Attack Mitigation

> **BCSE308P — Computer Networks Project**  
> **Core Objective:** Real-Time Network Intrusion Detection & Security Alerting  
> **Advanced Extension:** Dynamic, Adaptive QoS-Based Traffic Mitigation & Feedback Loop

---

## 1. Project Overview & Problem Statement Alignment

| Problem Statement Requirement | Project Component & Implementation |
| :--- | :--- |
| **Identify suspicious activities** | Unsupervised Machine Learning (Isolation Forest Anomaly Detector) |
| **Identify potential attacks** | Hybrid Detection: Rule-based Signatures + Random Forest Classifier |
| **Analyze network environment** | Live packet sniffing (Scapy) and 5-tuple bidirectional session flow tracking |
| **Generate alerts** | SQLite Alert Manager with deduplication and real-time WebSockets dispatch |
| **Detect known attacks** | Signature engine with configurable rules (`SIG-001` to `SIG-006`) |
| **Detect unknown/anomalous behavior** | Isolation Forest trained on benign flow baselines (Zero-Day Anomaly detection) |
| **Improve detection reliability** | Decision/Fusion Layer with Agreement Matrix and Weighted Risk Scoring |
| **Respond to detected attacks** | Adaptive QoS mitigation (Linux `tc`/HTB driver + cross-platform virtual QoS) |
| **Real-time operation** | Instantaneous packet processing, 1-second telemetry ticks, live SOC dashboard |
| **System evaluation** | Detection accuracy (100%), F1-Score (93.5%), low FPR (8.0%), latency & QoS impact |

---

## 2. Architecture & Flow Diagram

```
                             Network Traffic
                         (Live Scapy / Synthetic)
                                    │
                                    ▼
                         Packet & Flow Capture
                       (5-tuple session tracking)
                                    │
                                    ▼
                         Flow Feature Extraction
                    (PPS, BPS, SYN/ACK Ratio, Ports)
                                    │
                     ┌──────────────┴──────────────┐
                     ▼                             ▼
           Signature Engine               ML Anomaly Engine
       (Port Scan, SYN Flood,          (Isolation Forest +
        ICMP/UDP Floods, Probes)        Random Forest Classifier)
                     │                             │
                     └──────────────┬──────────────┘
                                    ▼
                         Decision / Fusion Layer
                      Risk = 0.6×Sig + 0.4×ML
                      Agreement Matrix Analysis
                                    │
                     ┌──────────────┴──────────────┐
                     ▼                             ▼
              [Normal Traffic]             [Malicious / Anomaly]
                                                   │
                                                   ▼
                                            Security Alert
                                        (SQLite + WebSockets)
                                                   │
                                                   ▼
                                         Adaptive QoS Response
                                         ┌─────────┴─────────┐
                                         ▼                   ▼
                                    Rate-Limit           Prioritize
                                    Attack Flow          Normal Flow
                                         │
                                         ▼
                                   Feedback Loop
                          (Traffic normalizes -> restore QoS)
```

---

## 3. Technology Stack

- **Core Language:** Python 3.13+
- **Packet Sniffing & Flow Analysis:** Scapy, Python Flow Manager
- **Machine Learning Models:** Scikit-learn (Isolation Forest, Random Forest Classifier)
- **Backend & Streaming:** FastAPI, Uvicorn, WebSockets
- **Database:** SQLite (`alerts.db`)
- **QoS Mitigation:** Linux `tc` / HTB queueing disciplines & Cross-Platform Virtual QoS Engine
- **Frontend Dashboard:** HTML5, Vanilla CSS (Dark Cyber SOC Glassmorphism), Chart.js

---

## 4. Setup and Quick Start

### 4.1 Prerequisites
- Python 3.10+ installed
- Virtual environment (`venv`)

### 4.2 Installation
```bash
# Clone or navigate to the project directory
cd "CN PROJECT"

# Activate the virtual environment
source venv/bin/activate

# Install dependencies (already prepared)
pip install -r requirements.txt
```

### 4.3 Training the ML Models
The models are already trained and saved under `models/`. To retrain at any time:
```bash
python -m training.train_models
```

### 4.4 Launching the System
Run the unified launcher:
```bash
python run.py
```
Open your browser and navigate to:
```
http://localhost:8050
```
- **Live SOC Dashboard:** `http://localhost:8050/`
- **Interactive REST API Docs:** `http://localhost:8050/docs`
- **Real-Time WebSockets Feed:** `ws://localhost:8050/ws`

---

## 5. Live Demonstration Scenarios

You can execute all test scenarios directly from the **dashboard buttons** or via the REST API:

### Test 1 — Normal Benign Traffic
- Normal web browsing (HTTP/HTTPS) and DNS requests are sent.
- **Result:** Both Signature and ML score 0%. Risk = `LOW` / `NORMAL`. Full bandwidth (100 Mbps, Priority 1) maintained.

### Test 2 — TCP Port Scan (`SIG-001`)
- Attacker rapidly probes multiple ports across the target host.
- **Result:** Signature flags `SIG-001`, ML anomaly score rises. Risk = `HIGH` (75–85%). **Action:** Automatic bandwidth throttling applied to `10.0.2.15`.

### Test 3 — TCP SYN Flood (`SIG-002`)
- High frequency burst of half-open TCP SYN packets with minimal ACK completions.
- **Result:** Agreement consensus triggers `CRITICAL` alert with Risk Score > 90%. **Action:** Immediate aggressive rate-limiting (256 Kbps).

### Test 4 — Zero-Day / Unknown Anomaly (Agreement Case 3)
- Attacker transmits packets with strange entropy, non-standard flag combinations (SYN+FIN+URG), and timing profiles that don't match any static signature rule.
- **Result:** Signature reports `NORMAL`, but Isolation Forest immediately catches the structural abnormality (`ANOMALY > 70%`). Fusion engine triggers a `ZERO_DAY_ANOMALY` alert and flags the IP for monitoring and soft rate-limiting. This clearly proves the superiority of the **hybrid architecture** over conventional signature-only NIDS!

### Test 5 — Dynamic Feedback Loop & QoS Recovery
- Stop or pause attack traffic.
- Once the attacker stops transmitting for the cooldown duration (15s by default), the feedback loop observes the normalization of traffic and systematically steps down restrictions (`CRITICAL` → `HIGH` → `SUSPICIOUS` → `NORMAL`), restoring normal bandwidth.

---

## 6. Evaluation Metrics


### Machine Learning Performance (Validated on Canonical Benchmark Flow Dataset)
- **Isolation Forest (Unsupervised Anomaly Detector):**
  - **Accuracy:** **90.78%**
  - **Precision:** **98.80%**
  - **Recall:** **88.31%**
  - **F1-Score:** **93.26%**
  - **False Positive Rate (FPR):** **2.80%**
- **Random Forest (Supervised Attack Classifier):**
  - **Overall Accuracy:** **100.00%** across 7 distinct traffic categories:
    - `BENIGN`
    - `PortScan`
    - `SYN_Flood`
    - `ICMP_Flood`
    - `UDP_Flood`
    - `BruteForce`
    - `DNS_Exfiltration` (Covert Data Tunneling)
  - **Top Predictive Features:** `syn_ack_ratio`, `avg_packet_size`, `syn_count`, `packet_count`, `byte_count`.

---

## 7. Comparative Analysis: This Project vs. NetSentinel
Comparing this platform against [`leelakrishnakurra97/network-traffic-anomaly-detection`](https://github.com/leelakrishnakurra97/network-traffic-anomaly-detection):

| Capability / Feature | NetSentinel (`leelakrishnakurra97`) | This Project (Real-Time Hybrid NIDS & Adaptive QoS) |
| :--- | :--- | :--- |
| **Detection Scope** | DNS traffic exclusively (Port 53) | **Full-Spectrum NIDS:** TCP, UDP, ICMP, HTTP/SSH, DNS |
| **Attack Vectors** | DNS Exfiltration & DGA | **SYN Floods, Port Scans, UDP Floods, ICMP Floods, Brute Force, DNS Tunneling & Zero-Days** |
| **Live Packet Sniffing** | ❌ None (Offline batch only) | **✅ Real-Time Scapy Sniffing & sliding-window flow tracking** |
| **Automated Defense / QoS**| ❌ Passive analysis only | **✅ Active Mitigation:** Dynamic rate-limiting, Priority Queues, Linux `tc` kernel driver & Virtual Token Bucket |
| **Dynamic Restoration** | ❌ None | **✅ Cooldown Feedback Loop:** Automatically restores bandwidth as traffic normalizes |
| **Wireshark Support** | ✅ PCAP & PCAPNG uploads | **✅ PCAP & PCAPNG uploads + built-in sample test traces** |
| **Telemetry & Alerts** | Poll-based REST | **✅ Real-Time WebSockets Streaming + Glassmorphism SOC Console** |

---

## 8. Project Structure

```
CN PROJECT/
├── run.py                      # Unified Launcher
├── requirements.txt            # Python dependencies
├── README.md                   # Complete documentation and review guide
├── config/
│   ├── settings.py             # Configuration parameters
│   └── rules.yaml              # Signature rules (SIG-001 to SIG-007)
├── data/
│   └── benchmark_nids_dataset.csv # Validated 7-class benchmark dataset
├── capture/
│   ├── flow_manager.py         # 5-tuple flow aggregation & aging
│   ├── packet_capture.py       # Scapy live capture & synthetic injection
│   └── pcap_analyzer.py        # Wireshark PCAP & PCAPNG offline forensics engine
├── features/
│   ├── schema.py               # Feature vector definition (14 flow features)
│   └── extractor.py            # Real-time feature calculation & Shannon entropy
├── detection/
│   ├── signature_engine.py     # Rule-based signature matching (SIG-001 to SIG-007)
│   ├── anomaly_detector.py     # Isolation Forest anomaly scoring
│   └── classifier.py           # Random Forest multi-class attack classifier
├── decision/
│   └── fusion_engine.py        # Weighted risk score & agreement matrix
├── mitigation/
│   ├── qos_controller.py       # QoS rate limits & dynamic feedback loop
│   └── drivers/
│       ├── linux_tc.py         # Linux tc / HTB kernel driver
│       └── virtual_qos.py      # Cross-platform token bucket driver
├── alerts/
│   └── alert_manager.py        # SQLite alert database & dispatch
├── uploads/
│   └── sample_pcaps/           # Bundled Wireshark PCAP/PCAPNG test traces
├── training/
│   ├── prepare_benchmark_data.py # Canonical benchmark dataset builder
│   ├── synthetic_data.py       # Synthetic flow generator
│   └── train_models.py         # Model training and validation pipeline
├── simulator/
│   └── traffic_generator.py    # Test traffic and attack injection
├── api/
│   ├── server.py               # FastAPI backend & WebSockets
│   └── routes.py               # REST API endpoints (inc. PCAP upload/forensics)
├── dashboard/
│   ├── index.html              # Modern dark-mode SOC console
│   ├── css/style.css           # Glassmorphism cyber styling
│   └── js/
│       ├── app.js              # WebSockets, PCAP handlers & DOM logic
│       └── charts.js           # Real-time Chart.js charts
└── tests/
    └── test_nids.py            # Automated test suite (10 comprehensive tests)
```

