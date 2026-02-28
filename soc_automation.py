"""
SOC Automation Toolkit
======================
Author: Shubham Singh | github.com/shubhamsingh99
Description: Automates IOC enrichment, alert triage, and incident reporting for SOC analysts.
"""

import requests
import json
import hashlib
import re
import argparse
from datetime import datetime

# ─── CONFIG ─────────────────────────────────────────────────────────────────
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"

HEADERS_VT = {"x-apikey": VT_API_KEY}
REPORT_PATH = "./reports/"

# ─── IOC ENRICHMENT ─────────────────────────────────────────────────────────

def check_ip_virustotal(ip: str) -> dict:
    """Check IP reputation on VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        resp = requests.get(url, headers=HEADERS_VT, timeout=10)
        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "ioc": ip,
            "type": "IP",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "verdict": "MALICIOUS" if stats.get("malicious", 0) > 3 else "CLEAN"
        }
    except Exception as e:
        return {"ioc": ip, "error": str(e)}


def check_hash_virustotal(file_hash: str) -> dict:
    """Check file hash reputation on VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    try:
        resp = requests.get(url, headers=HEADERS_VT, timeout=10)
        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "ioc": file_hash,
            "type": "HASH",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "verdict": "MALICIOUS" if stats.get("malicious", 0) > 5 else "CLEAN"
        }
    except Exception as e:
        return {"ioc": file_hash, "error": str(e)}


def check_ip_abuseipdb(ip: str) -> dict:
    """Check IP on AbuseIPDB for abuse reports."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        data = resp.json().get("data", {})
        return {
            "ioc": ip,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", "Unknown"),
            "verdict": "HIGH RISK" if data.get("abuseConfidenceScore", 0) > 50 else "LOW RISK"
        }
    except Exception as e:
        return {"ioc": ip, "error": str(e)}


# ─── ALERT TRIAGE ────────────────────────────────────────────────────────────

def triage_alert(alert: dict) -> dict:
    """
    Auto-triage a SIEM alert based on IOCs.
    Maps findings to MITRE ATT&CK techniques.
    """
    results = []
    mitre_tags = []
    severity = "LOW"

    iocs = alert.get("iocs", {})

    # Enrich IPs
    for ip in iocs.get("ips", []):
        result = check_ip_virustotal(ip)
        results.append(result)
        if result.get("verdict") == "MALICIOUS":
            severity = "HIGH"
            mitre_tags.append("T1071 - Application Layer Protocol")

    # Enrich hashes
    for h in iocs.get("hashes", []):
        result = check_hash_virustotal(h)
        results.append(result)
        if result.get("verdict") == "MALICIOUS":
            severity = "CRITICAL"
            mitre_tags.append("T1204 - User Execution")
            mitre_tags.append("T1059 - Command and Scripting Interpreter")

    return {
        "alert_id": alert.get("alert_id"),
        "timestamp": datetime.utcnow().isoformat(),
        "severity": severity,
        "mitre_techniques": list(set(mitre_tags)),
        "enrichment_results": results,
        "recommended_action": (
            "ESCALATE TO TIER-2" if severity in ["HIGH", "CRITICAL"]
            else "MONITOR AND CLOSE"
        )
    }


# ─── REPORT GENERATOR ────────────────────────────────────────────────────────

def generate_report(triage_result: dict) -> str:
    """Generate a markdown incident report."""
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    alert_id = triage_result.get("alert_id", "N/A")
    severity = triage_result.get("severity", "UNKNOWN")
    techniques = "\n".join(f"  - {t}" for t in triage_result.get("mitre_techniques", []))
    action = triage_result.get("recommended_action", "N/A")

    enrichment_text = ""
    for r in triage_result.get("enrichment_results", []):
        enrichment_text += f"\n| {r.get('ioc')} | {r.get('type','N/A')} | {r.get('verdict','N/A')} |"

    report = f"""# 🔒 Incident Report
**Alert ID:** {alert_id}  
**Generated:** {now}  
**Severity:** {severity}  
**Analyst:** Shubham Singh  

---

## MITRE ATT&CK Techniques Identified
{techniques if techniques else '  - None identified'}

## IOC Enrichment Results

| IOC | Type | Verdict |
|-----|------|---------|{enrichment_text}

## Recommended Action
> **{action}**

---
*Generated by SOC-Automation-Toolkit | github.com/shubhamsingh99*
"""

    filename = f"{REPORT_PATH}report_{alert_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md"
    with open(filename, "w") as f:
        f.write(report)
    print(f"[+] Report saved to {filename}")
    return report


# ─── MAIN ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SOC Automation Toolkit by Shubham Singh")
    parser.add_argument("--ip", help="Check a single IP address")
    parser.add_argument("--hash", help="Check a file hash (MD5/SHA256)")
    parser.add_argument("--alert", help="Path to JSON alert file for full triage")
    args = parser.parse_args()

    if args.ip:
        print(json.dumps(check_ip_virustotal(args.ip), indent=2))
        print(json.dumps(check_ip_abuseipdb(args.ip), indent=2))

    elif args.hash:
        print(json.dumps(check_hash_virustotal(args.hash), indent=2))

    elif args.alert:
        with open(args.alert) as f:
            alert = json.load(f)
        result = triage_alert(alert)
        print(json.dumps(result, indent=2))
        generate_report(result)

    else:
        # Demo mode
        demo_alert = {
            "alert_id": "DEMO-2024-001",
            "iocs": {
                "ips": ["8.8.8.8"],  # Replace with actual suspicious IPs
                "hashes": []
            }
        }
        print("[*] Running in demo mode...")
        result = triage_alert(demo_alert)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
