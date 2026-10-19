# Real-Time Network Packet Sniffer & Anomaly Detector (`packet-sniffer-detector`)

A high-performance, asynchronous network packet capture and intrusion detection pipeline built in Python with **Scapy**, **SQLite WAL**, and **Rich**. 

The engine implements a decoupled producer-consumer architecture to achieve 1,200+ packets/second drop-free processing, dual-mode live/offline analysis, and mathematically calibrated heuristics for ARP spoofing, TCP SYN flooding, and TCP port scanning.

---

## Key Architectural Highlights

1. **Decoupled Producer-Consumer Pipeline:**
   - **Capture Producer Thread:** Reads raw Ethernet/IP frames from live network adapters or offline PCAP streams into a bounded `queue.Queue(maxsize=10000)`. Performs zero disk I/O to maximize capture throughput.
   - **Analysis Consumer Thread:** Dequeues packets, parses protocol layers, evaluates anomaly detection heuristics, and batches forensic writes to SQLite.
   - **Throughput & Zero-Drop Guarantee:** Drop counting monitors queue saturation; lazy hex serialization avoids per-packet string allocations until an alert fires.

2. **Multi-Layer Frame Parsing:**
   - **Layer 2 (Ethernet):** Source/Destination MAC addresses, EtherType identification.
   - **Layer 2.5 (ARP):** Operation codes (Request vs. Reply), target/sender hardware and protocol mappings.
   - **Layer 3 (IPv4):** Source/Destination IP, Protocol type, TTL.
   - **Layer 4 (TCP, UDP, ICMP):** Source/Destination ports, TCP control flags (`SYN`, `ACK`, `FIN`, `RST`), ICMP type and code.

3. **Calibrated Heuristic Detection Engines:**
   - **ARP Poisoning Detection:** Detects gratuitous and unsolicited ARP replies that alter known IP-to-MAC associations.
   - **TCP SYN Flood Detection:** Tracks sliding 1-second windows of `SYN` requests vs. completed `ACK` handshakes per target IP. Fails safe against legitimate high-traffic web endpoints by enforcing a $< 10\%$ ACK completion threshold before alerting.
   - **TCP Port Scan Detection:** Tracks unique destination ports contacted by a single source IP in a sliding 5-second window ($> 25$ unique ports).
   - **Alert Throttling & Memory Eviction:** Prevents alert storms via a 5-second cooldown per alert key and runs periodic state sweeps to evict idle IPs and avoid memory leaks.

4. **Forensic Database with SQLite WAL:**
   - Persists attack metadata, timestamps (UTC ISO), source/target IPs and ports, attack descriptions, and raw packet hex dumps.
   - Configured with `PRAGMA journal_mode = WAL;` and `PRAGMA synchronous = NORMAL;` with batched writes (`log_alerts_batch`) to eliminate disk thrashing.

5. **Dual-Mode Operation:**
   - **Live Adapter Mode:** Sniffs live traffic on Windows (Npcap driver) or Linux (`libpcap`).
   - **Offline PCAP Replay Mode:** Allows deterministic CI/CD test runs and forensic inspection without root or administrative privileges.

---

## Directory Structure

```text
packet-sniffer-detector/
├── sniffer/
│   ├── __init__.py
│   ├── decoder.py        # Frame decoder (Ethernet, IPv4, TCP, UDP, ICMP, ARP)
│   ├── detector.py       # Heuristic engines with ACK-ratio tracking & throttling
│   ├── database.py       # Forensic SQLite WAL pipeline with batching
│   └── runner.py         # Asynchronous producer-consumer capture runner
├── tests/
│   ├── __init__.py
│   └── test_sniffer.py   # Automated pytest suite with synthetic Scapy packets
├── cli.py                # Live terminal dashboard (Rich)
├── generate_demo_pcap.py # Synthetic attack generator script
├── demo.pcap             # Sample PCAP with benign and attack traffic
├── requirements.txt
└── README.md
```

---

## Quickstart

### 1. Environment Setup

```powershell
# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Offline PCAP Replay (No Admin Required)

```powershell
# Generate synthetic traffic PCAP
python generate_demo_pcap.py

# Replay PCAP through sniffer dashboard
python cli.py --pcap demo.pcap
```

### 3. Run Live Packet Capture (Requires Administrator / Npcap on Windows)

```powershell
# List available network adapters
python cli.py --list-interfaces

# Sniff live traffic on an adapter with an optional BPF filter
python cli.py --interface "\Device\NPF_{...}" --filter "tcp or arp"
```

### 4. Query Forensic Alert Database

```powershell
python cli.py --view-alerts
```

### 5. Run Automated Test Suite

```powershell
pytest -v
```
