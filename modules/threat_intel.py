"""
Threat Intelligence Module
Checks IPs against a local blocklist + simulates feed matching.
In production: integrate AbuseIPDB API, Feodo Tracker, etc.
"""
import re

# Simulated threat feed — replace with live API calls
THREAT_FEED = {
    "45.33.32.156":   {"category": "Scanner",       "threat": "HIGH",     "source": "Shodan scanner node",        "country": "US"},
    "192.168.1.105":  {"category": "Brute-force",   "threat": "CRITICAL", "source": "Internal threat actor",      "country": "LAN"},
    "203.0.113.9":    {"category": "Botnet C2",      "threat": "CRITICAL", "source": "Feodo Tracker — Emotet C2",  "country": "RU"},
    "10.0.0.99":      {"category": "Brute-force",   "threat": "HIGH",     "source": "Internal scan",              "country": "LAN"},
    "185.220.101.42": {"category": "Tor exit node",  "threat": "HIGH",     "source": "TorDNSEL",                   "country": "DE"},
    "91.108.4.1":     {"category": "Malware dist.",  "threat": "CRITICAL", "source": "AbuseIPDB top-100",          "country": "NL"},
}

def check_ips(ip_list):
    results = []
    for ip in ip_list:
        ip = ip.strip()
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            continue
        if ip in THREAT_FEED:
            entry = THREAT_FEED[ip].copy()
            entry["ip"]     = ip
            entry["status"] = "MATCH"
        else:
            entry = {
                "ip":       ip,
                "status":   "CLEAN",
                "threat":   "LOW",
                "category": "No known threat",
                "source":   "Not in feed",
                "country":  "Unknown",
            }
        results.append(entry)

    matched   = sum(1 for r in results if r["status"] == "MATCH")
    critical  = sum(1 for r in results if r.get("threat") == "CRITICAL")

    return {
        "total_checked": len(results),
        "matched":       matched,
        "critical":      critical,
        "results":       results,
    }
