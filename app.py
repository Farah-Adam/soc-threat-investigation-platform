"""
=============================================================
  PHASE 5 — SOC WEB PLATFORM
  Flask backend connecting all 4 modules
=============================================================
  Install:  pip install flask
  Run:      python app.py
  Open:     http://localhost:5000
=============================================================
"""

import os, json
from flask import Flask, render_template, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from datetime import datetime

# Import SOC modules
from modules.log_analyzer   import analyze_log
from modules.network_scanner import scan_host_quick
from modules.packet_analyzer import run_demo_analysis, analyze_pcap

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["REPORT_FOLDER"] = "reports"
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32 MB

ALLOWED_LOG  = {"log", "txt", ""}
ALLOWED_PCAP = {"pcap", "pcapng", "cap"}

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["REPORT_FOLDER"], exist_ok=True)


# ─── ROUTES ────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── Module 1: Log Analyzer ─────────────────────────────────

@app.route("/api/log/analyze", methods=["POST"])
def api_log_analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    filename = secure_filename(f.filename)
    path     = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    f.save(path)

    try:
        result = analyze_log(path)
        _save_report("log", result)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/log/demo", methods=["GET"])
def api_log_demo():
    demo_path = os.path.join(app.config["UPLOAD_FOLDER"], "demo_auth.log")
    _write_demo_log(demo_path)
    result = analyze_log(demo_path)
    return jsonify(result)


# ── Module 2: Network Scanner ──────────────────────────────

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data   = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"error": "No target provided"}), 400

    # Basic IP/hostname validation
    import re
    if not re.match(r"^[\w.\-]+$", target):
        return jsonify({"error": "Invalid target"}), 400

    try:
        result = scan_host_quick(target)
        _save_report("scan", result)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Module 3: Packet Analyzer ──────────────────────────────

@app.route("/api/packet/demo", methods=["GET"])
def api_packet_demo():
    result = run_demo_analysis()
    return jsonify(result)


@app.route("/api/packet/analyze", methods=["POST"])
def api_packet_analyze():
    if "file" not in request.files:
        return jsonify({"error": "No pcap uploaded"}), 400

    f   = request.files["file"]
    ext = f.filename.rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED_PCAP:
        return jsonify({"error": "Must be a .pcap / .pcapng file"}), 400

    filename = secure_filename(f.filename)
    path     = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    f.save(path)

    try:
        result = analyze_pcap(path)
        _save_report("packet", result)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Module 4: Threat Intelligence ─────────────────────────

@app.route("/api/threat/check", methods=["POST"])
def api_threat_check():
    data = request.get_json(silent=True) or {}
    ips  = data.get("ips", [])
    if not ips:
        return jsonify({"error": "No IPs provided"}), 400

    from modules.threat_intel import check_ips
    result = check_ips(ips)
    return jsonify(result)


# ── Report export ──────────────────────────────────────────

@app.route("/api/report/export", methods=["POST"])
def api_export():
    data = request.get_json(silent=True) or {}
    name = f"soc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    path = os.path.join(app.config["REPORT_FOLDER"], name)
    with open(path, "w") as fp:
        json.dump(data, fp, indent=2)
    return jsonify({"file": name, "message": f"Saved as {name}"})


@app.route("/reports/<filename>")
def download_report(filename):
    return send_from_directory(app.config["REPORT_FOLDER"], filename, as_attachment=True)


# ─── HELPERS ───────────────────────────────────────────────

def _save_report(module, data):
    name = f"{module}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(os.path.join(app.config["REPORT_FOLDER"], name), "w") as f:
        json.dump(data, f, indent=2)


def _write_demo_log(path):
    lines = [
        "Apr  1 02:10:01 server sshd[1]: Failed password for root from 192.168.1.105 port 54321 ssh2",
        "Apr  1 02:10:03 server sshd[1]: Failed password for root from 192.168.1.105 port 54322 ssh2",
        "Apr  1 02:10:05 server sshd[1]: Failed password for admin from 192.168.1.105 port 54323 ssh2",
        "Apr  1 02:10:07 server sshd[1]: Failed password for admin from 192.168.1.105 port 54324 ssh2",
        "Apr  1 02:10:09 server sshd[1]: Failed password for ubuntu from 192.168.1.105 port 54325 ssh2",
        "Apr  1 02:10:11 server sshd[1]: Failed password for ubuntu from 192.168.1.105 port 54326 ssh2",
        "Apr  1 02:10:13 server sshd[1]: Failed password for root from 192.168.1.105 port 54327 ssh2",
        "Apr  1 02:10:15 server sshd[1]: Failed password for root from 192.168.1.105 port 54328 ssh2",
        "Apr  1 02:10:42 server sshd[1]: Accepted password for root from 192.168.1.105 port 54341 ssh2",
        "Apr  1 03:00:00 server sshd[2]: Invalid user oracle from 45.33.32.156 port 10001 ssh2",
        "Apr  1 03:00:02 server sshd[2]: Invalid user postgres from 45.33.32.156 port 10002 ssh2",
        "Apr  1 03:00:04 server sshd[2]: Invalid user deploy from 45.33.32.156 port 10003 ssh2",
        "Apr  1 03:00:06 server sshd[2]: Invalid user git from 45.33.32.156 port 10004 ssh2",
        "Apr  1 03:00:08 server sshd[2]: Invalid user ftp from 45.33.32.156 port 10005 ssh2",
        "Apr  1 04:15:00 server sshd[3]: Failed password for root from 10.0.0.99 port 22001 ssh2",
        "Apr  1 04:15:04 server sshd[3]: Failed password for root from 10.0.0.99 port 22002 ssh2",
        "Apr  1 04:15:08 server sshd[3]: Failed password for admin from 10.0.0.99 port 22003 ssh2",
        "Apr  1 04:15:12 server sshd[3]: Failed password for ubuntu from 10.0.0.99 port 22004 ssh2",
        "Apr  1 04:15:16 server sshd[3]: Failed password for user from 10.0.0.99 port 22005 ssh2",
        "Apr  1 04:15:20 server sshd[3]: Failed password for root from 10.0.0.99 port 22006 ssh2",
        "Apr  1 05:00:00 server sshd[4]: Accepted publickey for deploy from 172.16.0.5 port 60001 ssh2",
        "Apr  1 05:30:00 server sshd[5]: Failed password for root from 203.0.113.9 port 11001 ssh2",
        "Apr  1 05:30:01 server sshd[5]: Failed password for root from 203.0.113.9 port 11002 ssh2",
        "Apr  1 05:30:02 server sshd[5]: Failed password for admin from 203.0.113.9 port 11003 ssh2",
        "Apr  1 05:30:03 server sshd[5]: Failed password for user from 203.0.113.9 port 11004 ssh2",
        "Apr  1 05:30:04 server sshd[5]: Failed password for test from 203.0.113.9 port 11005 ssh2",
        "Apr  1 05:30:05 server sshd[5]: Failed password for root from 203.0.113.9 port 11006 ssh2",
        "Apr  1 05:30:06 server sshd[5]: Failed password for root from 203.0.113.9 port 11007 ssh2",
        "Apr  1 05:30:07 server sshd[5]: Failed password for root from 203.0.113.9 port 11008 ssh2",
        "Apr  1 06:00:00 server sshd[6]: Accepted password for alice from 198.51.100.1 port 33301 ssh2",
    ]
    with open(path, "w") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    print("\n  SOC Platform running at http://localhost:5000\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
