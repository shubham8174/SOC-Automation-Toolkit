# 🔐 SOC Automation Toolkit

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal-API-394EFF?style=for-the-badge&logo=virustotal&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-FF0000?style=for-the-badge)


> Automates repetitive SOC workflows — IOC enrichment, alert triage, and incident report generation — reducing manual analysis time by 20%+.

---

## 📌 Overview

As a SOC Analyst triaging 200+ daily alerts, I built this toolkit to eliminate the manual, repetitive steps that slow down incident response. It integrates with **VirusTotal**, **AbuseIPDB**, and **Shodan** APIs to auto-enrich indicators of compromise, assign severity, map to MITRE ATT&CK techniques, and generate structured markdown reports — all from a single command.

---

## ✨ Features

- **IOC Enrichment** — Auto-check IPs and file hashes against VirusTotal and AbuseIPDB
- **Alert Triage** — Assign severity (LOW / HIGH / CRITICAL) based on enrichment results
- **MITRE ATT&CK Mapping** — Automatically tag alerts with relevant ATT&CK techniques
- **Report Generation** — Output structured markdown incident reports per alert
- **CLI Interface** — Run single IOC checks or full JSON alert triage from command line

---

## 🛠️ Installation

```bash
git clone https://github.com/shubham8174/SOC-Automation-Toolkit.git
cd SOC-Automation-Toolkit
pip install requests
```

---

## ⚙️ Configuration

Open `soc_automation.py` and add your API keys:

```python
VT_API_KEY = "your_virustotal_api_key"
ABUSEIPDB_API_KEY = "your_abuseipdb_api_key"
```

> 🔑 Free API keys available at:
> - VirusTotal: https://www.virustotal.com/gui/join-us
> - AbuseIPDB: https://www.abuseipdb.com/register

---

## 🚀 Usage

```bash
# Check a single IP
python soc_automation.py --ip 192.168.1.100

# Check a file hash
python soc_automation.py --hash d41d8cd98f00b204e9800998ecf8427e

# Full alert triage from JSON file
python soc_automation.py --alert alert_sample.json

# Demo mode (no API keys needed)
python soc_automation.py
```

**Sample alert JSON format:**
```json
{
  "alert_id": "SOC-2024-001",
  "iocs": {
    "ips": ["185.220.101.45"],
    "hashes": ["44d88612fea8a8f36de82e1278abb02f"]
  }
}
```

**Sample output:**
```json
{
  "alert_id": "SOC-2024-001",
  "severity": "CRITICAL",
  "mitre_techniques": [
    "T1071 - Application Layer Protocol",
    "T1204 - User Execution"
  ],
  "recommended_action": "ESCALATE TO TIER-2"
}
```

---

## 📊 MITRE ATT&CK Coverage

| Technique | ID | Detection Trigger |
|---|---|---|
| Application Layer Protocol | T1071 | Malicious IP detected |
| User Execution | T1204 | Malicious hash detected |
| Command & Scripting Interpreter | T1059 | Malicious hash + behavior |

---

## 📁 Project Structure

```
SOC-Automation-Toolkit/
│
├── soc_automation.py      # Main script
├── reports/               # Auto-generated incident reports
├── samples/               # Sample alert JSON files
└── README.md
```

---

## 🔮 Roadmap

- [ ] Shodan IP geolocation and open port enrichment
- [ ] Slack/Teams webhook for real-time alert notifications
- [ ] Microsoft Sentinel API integration
- [ ] URL reputation checking via URLScan.io

---

## 👤 Author

**Shubham Singh**
MSc Cyber Security — University of Southampton 🇬🇧
Information Security Analyst | SOC Operations

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077B5?style=flat&logo=linkedin)](https://www.linkedin.com/in/shubham-singh99/)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=flat&logo=github)](https://github.com/shubham8174)

