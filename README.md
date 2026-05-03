# SOC Threat Investigation Platform

## Quick Start

```bash
# 1. Install dependencies
pip install flask werkzeug

# 2. Start the server
python app.py

# 3. Open in browser
http://localhost:5000
```

## Project Structure

```
soc_platform/
├── app.py                    ← Flask backend (main entry point)
├── requirements.txt
├── modules/
│   ├── log_analyzer.py       ← Phase 1: brute-force / SSH detection
│   ├── network_scanner.py    ← Phase 2: TCP port scan + banner grab
│   ├── packet_analyzer.py    ← Phase 3: SQLi / XSS / ReverseShell
│   └── threat_intel.py       ← Phase 4: IP reputation matching
├── templates/
│   └── index.html            ← Full dashboard UI
├── uploads/                  ← Uploaded log / pcap files
└── reports/                  ← Exported JSON reports
```

## API Endpoints

| Method | Endpoint              | Description                    |
|--------|-----------------------|--------------------------------|
| GET    | /                     | Dashboard UI                   |
| GET    | /api/log/demo         | Run log analysis on demo data  |
| POST   | /api/log/analyze      | Analyze uploaded auth.log      |
| POST   | /api/scan             | Scan target IP/hostname        |
| GET    | /api/packet/demo      | Run packet analysis on demo    |
| POST   | /api/packet/analyze   | Analyze uploaded .pcap file    |
| POST   | /api/threat/check     | Check IPs against threat feed  |
| POST   | /api/report/export    | Export full investigation JSON |

## Modules

### Module 1 — Log Analyzer
- Upload any auth.log / syslog file
- Detects brute-force (sliding 60s window)
- Detects successful login after failures (CRITICAL)
- Detects invalid username scanning

### Module 2 — Network Scanner
- Enter any IP or hostname
- Scans top 24 common ports concurrently
- Grabs service banners (SSH version, Apache, MySQL...)
- Risk-rates every open port with explanation

### Module 3 — Packet Analyzer
- Upload .pcap from Wireshark or run built-in demo
- Detects: SQLi, XSS, CMDi, PathTraversal, ReverseShell, Obfuscation
- Decodes base64 and URL-encoded payloads before scanning

### Module 4 — Threat Intelligence
- Enter IPs (one per line) to check
- Matches against local blocklist (extend with live API)
- Shows threat category, source, and country

### Incident Report
- Auto-generates from all completed module runs
- Downloadable as JSON
- Print to PDF via browser

## Extending Threat Intel with Live APIs

```python
# In modules/threat_intel.py, add:
import requests

def check_abuseipdb(ip, api_key):
    r = requests.get(
        'https://api.abuseipdb.com/api/v2/check',
        headers={'Key': api_key, 'Accept': 'application/json'},
        params={'ipAddress': ip, 'maxAgeInDays': 90}
    )
    return r.json()['data']
```
