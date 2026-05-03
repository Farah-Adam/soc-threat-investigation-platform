import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

TOP_PORTS = [21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,6379,8080,8443,8888,27017]
TIMEOUT   = 0.8

PORT_RISK = {
    21:    ("FTP",        "HIGH",     "Cleartext file transfer — credentials exposed"),
    22:    ("SSH",        "MEDIUM",   "Encrypted shell — monitor for brute-force"),
    23:    ("Telnet",     "CRITICAL", "Cleartext remote shell — replace with SSH"),
    25:    ("SMTP",       "MEDIUM",   "Mail relay — check for open relay"),
    53:    ("DNS",        "MEDIUM",   "DNS — check zone transfer & amplification"),
    80:    ("HTTP",       "MEDIUM",   "Cleartext web — check for sensitive pages"),
    110:   ("POP3",       "HIGH",     "Cleartext email retrieval"),
    135:   ("MS-RPC",     "HIGH",     "Windows RPC — frequent exploit target"),
    139:   ("NetBIOS",    "HIGH",     "Legacy SMB — many known vulnerabilities"),
    143:   ("IMAP",       "MEDIUM",   "Cleartext IMAP — credentials exposed"),
    443:   ("HTTPS",      "LOW",      "Encrypted web — audit TLS version"),
    445:   ("SMB",        "CRITICAL", "EternalBlue / ransomware vector"),
    993:   ("IMAPS",      "LOW",      "Encrypted IMAP — audit certificate"),
    995:   ("POP3S",      "LOW",      "Encrypted POP3 — audit certificate"),
    1723:  ("PPTP",       "HIGH",     "Deprecated VPN — weak crypto"),
    3306:  ("MySQL",      "CRITICAL", "Database — should never be internet-facing"),
    3389:  ("RDP",        "HIGH",     "Remote Desktop — BlueKeep, brute-force target"),
    5432:  ("PostgreSQL", "CRITICAL", "Database — restrict to localhost only"),
    5900:  ("VNC",        "HIGH",     "Cleartext remote desktop — enforce auth"),
    6379:  ("Redis",      "CRITICAL", "Default config has no auth"),
    8080:  ("HTTP-Alt",   "MEDIUM",   "Dev/proxy server — often misconfigured"),
    8443:  ("HTTPS-Alt",  "MEDIUM",   "Alt HTTPS — verify access controls"),
    8888:  ("Jupyter",    "CRITICAL", "Jupyter Notebook — often no auth, full RCE"),
    27017: ("MongoDB",    "CRITICAL", "Database — notorious open instances"),
}

def _scan_port(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        if s.connect_ex((host, port)) == 0:
            s.close()
            return port
        s.close()
    except: pass
    return None

def _grab_banner(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        s.connect((host, port))
        probe = b"HEAD / HTTP/1.0\r\n\r\n" if port in (80,8080,8443) else b"\r\n"
        s.send(probe)
        banner = s.recv(256).decode("utf-8", errors="replace").strip().splitlines()
        s.close()
        return banner[0][:80] if banner else ""
    except: return ""

def scan_host_quick(target):
    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as ex:
        results = list(ex.map(lambda p: _scan_port(target, p), TOP_PORTS))
    open_ports = [p for p in results if p]

    enriched = []
    for port in open_ports:
        svc, risk, reason = PORT_RISK.get(port, ("Unknown","INFO","Unrecognised service"))
        banner = _grab_banner(target, port)
        enriched.append({
            "port": port, "service": svc, "risk": risk,
            "reason": reason, "banner": banner,
        })

    enriched.sort(key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}.get(x["risk"],9))

    crit = sum(1 for p in enriched if p["risk"] == "CRITICAL")
    high = sum(1 for p in enriched if p["risk"] == "HIGH")

    return {
        "host": target,
        "scanned_at": datetime.now().isoformat(),
        "open_count": len(enriched),
        "critical_count": crit,
        "high_count": high,
        "ports": enriched,
    }
