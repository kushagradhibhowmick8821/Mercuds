# 🛡️ Mercuds - Network Intrusion Detection System

A modular, extensible network monitoring and intrusion detection prototype.

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Root/sudo access (for packet capture)
- macOS/Linux

### Installation

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the monitor (requires sudo for packet capture)
cd network_monitor
sudo python main.py
```

### Basic Usage

```bash
# Monitor default interface
sudo python main.py

# Monitor specific interface
sudo python main.py -i en0

# Filter specific traffic
sudo python main.py -f "tcp port 80 or tcp port 443"

# List available interfaces
python main.py --list-interfaces
```

## 📁 Project Structure

```
Mercuds/
├── network_monitor/          # Network monitoring module
│   ├── __init__.py
│   ├── main.py              # Entry point
│   ├── sniffer.py           # Packet capture engine
│   ├── analyzer.py          # Traffic analysis & anomaly detection
│   ├── dashboard.py         # Real-time terminal UI
│   └── threat_intel.py      # Threat intelligence management
├── threat_data/             # Threat indicator storage (auto-created)
├── logs/                    # Alert logs (auto-created)
├── requirements.txt
└── README.md
```

## 🔍 Detection Capabilities

### Current Detections (v0.1)
- ✅ **Port Scanning** - Detects hosts probing multiple ports
- ✅ **Suspicious Ports** - Alerts on known malware/backdoor ports
- ✅ **Connection Flooding** - Detects DoS/DDoS patterns
- ✅ **Data Exfiltration** - Large data transfers to single destination
- ✅ **Protocol Anomalies** - DNS tunneling, ICMP tunneling

### Planned Detections
- 🔲 ARP spoofing detection
- 🔲 Machine learning anomaly detection
- 🔲 Signature-based detection (like Snort rules)
- 🔲 Encrypted traffic analysis
- 🔲 Lateral movement detection

## 🎯 Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Sniffer   │────▶│  Analyzer   │────▶│  Dashboard  │
│             │     │             │     │             │
│ • Capture   │     │ • Detection │     │ • Display   │
│ • Parse     │     │ • Alerting  │     │ • Logging   │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │ Threat Intel│
                    │             │
                    │ • IP Lists  │
                    │ • Signatures│
                    └─────────────┘
```

## 🔧 Configuration

### Analyzer Thresholds (in `analyzer.py`)

```python
self.thresholds = {
    "port_scan_threshold": 20,       # Ports/min to trigger alert
    "connection_rate_threshold": 50, # Connections/min
    "data_exfil_threshold": 10_000_000,  # 10MB
    "time_window_seconds": 60
}
```

### Adding Custom Threat Indicators

Create files in `threat_data/`:
- `malicious_ips.txt` - One IP per line
- `malicious_domains.txt` - One domain per line

---

## 🛣️ Development Roadmap

> **Philosophy:** Feature-focused, implementation-flexible. Each phase builds on the previous. Structure emerges from needs, not predefined templates.

---

### 📍 Phase 1: Network Monitor (Current - v0.1)
**Goal:** Real-time network visibility and basic threat detection

**Completed:**
- [x] Packet capture (TCP/UDP/ICMP/DNS/ARP)
- [x] Real-time terminal dashboard
- [x] Basic anomaly detection (port scan, flood, exfil)
- [x] Alert logging

**To Complete:**
- [ ] Connection state tracking (TCP handshake analysis)
- [ ] ARP spoofing detection
- [ ] MAC address anomaly detection
- [ ] GeoIP enrichment for external IPs
- [ ] Session/stream reconstruction
- [ ] Export formats (JSON, CSV, PCAP)

---

### 🔷 Phase 2: Intelligent Detection (v0.2 - v0.4)
**Goal:** Move beyond static rules to behavioral and ML-based detection

**Core Features:**
- [ ] Baseline learning (establish "normal" network behavior)
- [ ] Anomaly scoring with confidence levels
- [ ] C2 beaconing detection (periodic callback patterns)
- [ ] DNS analytics (DGA detection, tunneling identification)
- [ ] TLS fingerprinting (JA3/JA3S hashes)
- [ ] Modular detection plugins (easy to add new detectors)

**Signature & Rules:**
- [ ] Snort/Suricata rule compatibility
- [ ] Custom rule language
- [ ] YARA integration for payload scanning

**Enrichment:**
- [ ] Threat intelligence API integration (VirusTotal, AbuseIPDB, etc.)
- [ ] WHOIS/ASN lookups
- [ ] Reputation scoring

---

### 🔷 Phase 3: Malware Analysis (v0.5 - v0.7)
**Goal:** Analyze suspicious files captured or submitted

**Static Analysis:**
- [ ] File hashing (MD5, SHA256, SSDeep fuzzy hashing)
- [ ] PE/ELF/Mach-O binary parsing
- [ ] String extraction & suspicious pattern detection
- [ ] Document analysis (Office macros, PDF JavaScript)
- [ ] YARA rule scanning

**Dynamic Analysis:**
- [ ] Sandbox integration (Cuckoo, CAPE, or custom)
- [ ] Behavioral monitoring (file, registry, network activity)
- [ ] API call tracing
- [ ] Memory forensics basics

**Reputation & Reporting:**
- [ ] External API lookups (VirusTotal, MalwareBazaar)
- [ ] Automated report generation
- [ ] IOC extraction from samples

---

### 🔷 Phase 4: Response & Automation (v0.8 - v0.9)
**Goal:** Move from detection to action

**Automated Response:**
- [ ] Firewall integration (block malicious IPs)
- [ ] Host quarantine capabilities
- [ ] TCP connection termination
- [ ] Response playbooks (YAML-based automation)

**Alerting & Integration:**
- [ ] Multi-channel notifications (Slack, Discord, Email, SMS)
- [ ] SIEM export (Splunk, ELK, syslog)
- [ ] Ticketing integration (Jira, ServiceNow)
- [ ] Webhook support for custom integrations

---

### 🔷 Phase 5: Interface & API (v1.0)
**Goal:** Make the system accessible and manageable

**REST API:**
- [ ] Full API coverage for all modules
- [ ] Authentication & role-based access
- [ ] Real-time streaming endpoints (WebSocket)

**Web Dashboard:**
- [ ] Live traffic visualization
- [ ] Alert management & triage
- [ ] Historical analysis & search
- [ ] Configuration management
- [ ] Custom dashboard widgets

**Data Management:**
- [ ] Persistent storage (configurable backend)
- [ ] Data retention policies
- [ ] Search & query interface

---

### 🔷 Phase 6: Enterprise & Advanced (v2.0+)
**Goal:** Scale, distribute, and innovate

**Distributed Architecture:**
- [ ] Lightweight sensor agents
- [ ] Central collection & correlation
- [ ] Horizontal scaling
- [ ] Multi-site deployment

**Threat Hunting:**
- [ ] Query language for hunting
- [ ] Retroactive IOC scanning
- [ ] Hypothesis-based hunting workflows
- [ ] Attack pattern library

**Deception Technology:**
- [ ] Dynamic honeypots
- [ ] Honeytokens (fake credentials, files)
- [ ] Attacker profiling through deception

**AI/ML Advanced:**
- [ ] LLM-powered alert triage
- [ ] Attack path prediction
- [ ] Automated investigation assistance
- [ ] Self-tuning detection thresholds

---

### 🎯 Core Principles

| Principle | Description |
|-----------|-------------|
| **Modular** | Each capability is independent and pluggable |
| **Extensible** | Easy to add new detectors, analyzers, integrations |
| **Open** | Standard formats, APIs, no vendor lock-in |
| **Practical** | Useful at each phase, not just when "complete" |
| **Learning** | System improves over time, adapts to environment |

---

### 🔮 Innovation Vision

What makes Mercuds different from existing solutions:

1. **Unified Platform** — Network monitoring + Malware analysis + Response in one system
2. **Developer-First** — CLI-native, scriptable, API-driven
3. **Adaptive Detection** — Learns your network, not just signature matching
4. **Built-in Deception** — Honeypots as first-class citizens
5. **AI-Augmented** — LLM assistance for investigation and triage
6. **Open Architecture** — Integrate with anything, replace any component

---

## ⚠️ Disclaimer

This is a prototype for educational purposes. Do not use in production without proper security review. Only monitor networks you own or have permission to monitor.

## 📜 License

MIT License - See LICENSE file
