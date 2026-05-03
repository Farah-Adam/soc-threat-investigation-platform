import re
from datetime import datetime
from collections import defaultdict

PATTERNS = {
    "failed_ssh":   re.compile(r"(\w{3}\s+\d+\s[\d:]+).*sshd.*Failed password.*from\s+([\d.]+)"),
    "invalid_user": re.compile(r"(\w{3}\s+\d+\s[\d:]+).*sshd.*Invalid user \S+ from\s+([\d.]+)"),
    "accepted_ssh": re.compile(r"(\w{3}\s+\d+\s[\d:]+).*sshd.*Accepted (?:password|publickey).*from\s+([\d.]+)"),
}
MONTH_MAP = {"Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,"Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12}
BRUTE_THRESHOLD = 5
TIME_WINDOW     = 60

def _parse_ts(ts):
    p = ts.split()
    m, d = MONTH_MAP.get(p[0],1), int(p[1])
    h,mn,s = map(int, p[2].split(":"))
    return datetime(datetime.now().year, m, d, h, mn, s)

def analyze_log(filepath):
    failed  = defaultdict(list)
    success = defaultdict(list)
    invalid = defaultdict(int)

    with open(filepath, "r", errors="replace") as f:
        lines = f.readlines()

    for line in lines:
        for event, pat in PATTERNS.items():
            m = pat.search(line)
            if not m: continue
            try:
                ts = _parse_ts(m.group(1))
                ip = m.group(2)
            except: continue
            if event == "failed_ssh":   failed[ip].append(ts)
            elif event == "invalid_user": invalid[ip] += 1
            elif event == "accepted_ssh": success[ip].append(ts)

    alerts = []

    # Brute force detection
    for ip, timestamps in failed.items():
        timestamps.sort()
        peak, window_start = 0, None
        for i, ts in enumerate(timestamps):
            count = sum(1 for t in timestamps[i:] if (t-ts).total_seconds() <= TIME_WINDOW)
            if count > peak:
                peak, window_start = count, ts
        if peak >= BRUTE_THRESHOLD:
            alerts.append({
                "ip": ip, "type": "BRUTE_FORCE",
                "severity": "HIGH" if peak < 20 else "CRITICAL",
                "peak_attempts": peak,
                "total_failures": len(timestamps),
                "first_seen": timestamps[0].strftime("%H:%M:%S"),
                "last_seen":  timestamps[-1].strftime("%H:%M:%S"),
            })

    # Brute force success
    for ip, stimes in success.items():
        failures = failed.get(ip, [])
        if len(failures) < 3: continue
        for st in stimes:
            recent = [f for f in failures if 0 <= (st-f).total_seconds() <= 300]
            if len(recent) >= 3:
                alerts.append({
                    "ip": ip, "type": "BRUTE_FORCE_SUCCESS",
                    "severity": "CRITICAL",
                    "failures_before": len(recent),
                    "success_at": st.strftime("%H:%M:%S"),
                    "description": f"Login succeeded after {len(recent)} failures",
                })

    # Invalid user scans
    for ip, count in invalid.items():
        if count >= 3:
            alerts.append({
                "ip": ip, "type": "INVALID_USER_SCAN",
                "severity": "HIGH" if count >= 10 else "MEDIUM",
                "count": count,
            })

    alerts.sort(key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x["severity"],9))

    return {
        "total_lines":     len(lines),
        "unique_ips":      len(set(list(failed)+list(success))),
        "total_failures":  sum(len(v) for v in failed.values()),
        "total_successes": sum(len(v) for v in success.values()),
        "alerts":          alerts,
        "all_ips":         list(set(list(failed)+list(success)+list(invalid))),
    }
