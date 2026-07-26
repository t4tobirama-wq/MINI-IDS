"""
Detector — ARP spoofing detection and payload attack-string scanning.

Detection modules
─────────────────
1. ARP Spoofing
   • ARP table conflict  — same IP maps to a different MAC than previously seen
   • Gratuitous ARP      — unsolicited ARP reply (op=2 without a prior request)
   • ARP flood           — excessive ARP traffic from a single source MAC

2. Payload Attack Strings  (TCP / UDP payload inspection)
   • SQL injection patterns
   • Cross-site scripting (XSS)
   • Command / OS injection
   • Directory traversal
   • Common shell / reverse-shell commands
"""

import re
import time
import threading
from collections import defaultdict

from scapy.all import ARP, TCP, UDP, IP, Raw

from alert_manager import (
    AlertManager,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
)

# ─── Configuration ────────────────────────────────────────────────────────────

ARP_FLOOD_THRESHOLD = 30        # ARP packets from 1 MAC in the time window
ARP_FLOOD_WINDOW    = 10        # seconds
ARP_ALERT_COOLDOWN  = 30        # suppress duplicate ARP alerts (seconds)

PAYLOAD_ALERT_COOLDOWN = 15     # suppress duplicate payload alerts (seconds)

# ─── Attack-string signatures ────────────────────────────────────────────────
# Each entry: (compiled regex, human label, severity)

_PAYLOAD_SIGNATURES: list[tuple[re.Pattern, str, str]] = [
    # SQL injection
    (re.compile(rb"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b.*\b(FROM|INTO|TABLE|SET|WHERE|ALL)\b)", re.I),
     "SQL Injection", SEVERITY_HIGH),
    (re.compile(rb"(\'\s*(OR|AND)\s+[\'\d].*=)", re.I),
     "SQL Injection (tautology)", SEVERITY_HIGH),
    (re.compile(rb"(;\s*(DROP|DELETE|UPDATE|INSERT)\s)", re.I),
     "SQL Injection (stacked query)", SEVERITY_HIGH),
    (re.compile(rb"(SLEEP\s*\(\s*\d+\s*\)|BENCHMARK\s*\()", re.I),
     "SQL Injection (time-based)", SEVERITY_HIGH),

    # XSS
    (re.compile(rb"(<\s*script[^>]*>)", re.I),
     "Cross-Site Scripting (XSS)", SEVERITY_HIGH),
    (re.compile(rb"(on(error|load|click|mouseover)\s*=)", re.I),
     "XSS (event handler)", SEVERITY_MEDIUM),
    (re.compile(rb"(javascript\s*:)", re.I),
     "XSS (javascript: URI)", SEVERITY_MEDIUM),

    # Command injection
    (re.compile(rb"(;\s*(ls|cat|id|whoami|uname|pwd|ifconfig|ipconfig|netstat|wget|curl)\b)", re.I),
     "OS Command Injection", SEVERITY_CRITICAL),
    (re.compile(rb"(\|\s*(ls|cat|id|whoami|uname|bash|sh|cmd|powershell))", re.I),
     "Pipe Command Injection", SEVERITY_CRITICAL),
    (re.compile(rb"(`[^`]*`)", re.I),
     "Backtick Command Injection", SEVERITY_HIGH),
    (re.compile(rb"(\$\(.*\))", re.I),
     "Sub-shell Command Injection", SEVERITY_HIGH),

    # Directory traversal
    (re.compile(rb"(\.\./\.\./|\.\.\\\.\.\\)", re.I),
     "Directory Traversal", SEVERITY_HIGH),
    (re.compile(rb"(/etc/(passwd|shadow|hosts)|/proc/self)", re.I),
     "Sensitive File Access", SEVERITY_CRITICAL),
    (re.compile(rb"(C:\\Windows\\System32)", re.I),
     "Windows System Path Access", SEVERITY_HIGH),

    # Reverse shells / payloads
    (re.compile(rb"(nc\s+-[elp]|ncat\s+-|/bin/(ba)?sh\s+-i|python\s+-c\s+.*(socket|subprocess))", re.I),
     "Reverse Shell Attempt", SEVERITY_CRITICAL),
    (re.compile(rb"(bash\s+-i\s+>&\s*/dev/tcp/)", re.I),
     "Bash Reverse Shell", SEVERITY_CRITICAL),

    # HTTP suspicious
    (re.compile(rb"(PUT\s+/|DELETE\s+/|TRACE\s+/|OPTIONS\s+/)", re.I),
     "Suspicious HTTP Method", SEVERITY_LOW),
]


# ─── Detector class ──────────────────────────────────────────────────────────

class Detector:
    """Analyses every sniffed packet for ARP spoofing and malicious payloads."""

    def __init__(self, alert_manager: AlertManager):
        self.am = alert_manager

        # ARP table: IP → first-seen MAC
        self._arp_table: dict[str, str] = {}
        self._arp_lock = threading.Lock()

        # ARP flood tracking: MAC → list of timestamps
        self._arp_flood: dict[str, list[float]] = defaultdict(list)

        # Cool-down tracking: (source, label) → last alert epoch
        self._cooldowns: dict[tuple[str, str], float] = {}
        self._cd_lock = threading.Lock()

    # ── Public entry point ────────────────────────────────────────────────

    def analyse(self, packet) -> None:
        """Called by the sniffer for every captured packet."""
        self.am.increment_stat("total_packets")

        if packet.haslayer(ARP):
            self.am.increment_stat("arp_packets")
            self._check_arp(packet)

        if packet.haslayer(TCP):
            self.am.increment_stat("tcp_packets")

        if packet.haslayer(UDP):
            self.am.increment_stat("udp_packets")

        # Payload inspection (TCP & UDP only)
        if packet.haslayer(Raw) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
            self._check_payload(packet)

    # ── ARP spoofing detection ────────────────────────────────────────────

    def _check_arp(self, packet) -> None:
        arp = packet[ARP]
        src_ip  = arp.psrc      # sender protocol (IP) address
        src_mac = arp.hwsrc     # sender hardware (MAC) address
        op      = arp.op        # 1 = request, 2 = reply

        now = time.time()

        # 1. ARP table conflict — possible spoof
        with self._arp_lock:
            if src_ip in self._arp_table:
                known_mac = self._arp_table[src_ip]
                if known_mac != src_mac:
                    if self._should_alert(src_ip, "ARP Spoof"):
                        self.am.add_alert(
                            alert_type="ARP Spoof",
                            severity=SEVERITY_CRITICAL,
                            source=src_ip,
                            description=(
                                f"MAC changed! {src_ip} was {known_mac}, "
                                f"now claims to be {src_mac} — possible ARP spoofing"
                            ),
                            details={
                                "original_mac": known_mac,
                                "new_mac": src_mac,
                                "ip": src_ip,
                            },
                        )
                    # Update table to the new MAC so we catch further changes
                    self._arp_table[src_ip] = src_mac
            else:
                self._arp_table[src_ip] = src_mac

        # 2. Gratuitous ARP — unsolicited reply
        if op == 2:  # is-at (reply)
            # A gratuitous ARP has sender IP == target IP
            if arp.psrc == arp.pdst:
                if self._should_alert(src_ip, "Gratuitous ARP"):
                    self.am.add_alert(
                        alert_type="Gratuitous ARP",
                        severity=SEVERITY_HIGH,
                        source=src_ip,
                        description=(
                            f"Gratuitous ARP reply from {src_mac} "
                            f"claiming IP {src_ip} — often used in ARP spoofing"
                        ),
                        details={"mac": src_mac, "ip": src_ip},
                    )

        # 3. ARP flood detection
        flood_list = self._arp_flood[src_mac]
        flood_list.append(now)
        # Trim to window
        self._arp_flood[src_mac] = [
            t for t in flood_list if now - t <= ARP_FLOOD_WINDOW
        ]
        if len(self._arp_flood[src_mac]) >= ARP_FLOOD_THRESHOLD:
            if self._should_alert(src_mac, "ARP Flood"):
                self.am.add_alert(
                    alert_type="ARP Flood",
                    severity=SEVERITY_HIGH,
                    source=src_mac,
                    description=(
                        f"ARP flood detected — {len(self._arp_flood[src_mac])} "
                        f"ARP packets from {src_mac} in {ARP_FLOOD_WINDOW}s"
                    ),
                    details={
                        "mac": src_mac,
                        "count": len(self._arp_flood[src_mac]),
                        "window": ARP_FLOOD_WINDOW,
                    },
                )

    # ── Payload attack-string scanning ────────────────────────────────────

    def _check_payload(self, packet) -> None:
        payload: bytes = packet[Raw].load
        src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"

        for pattern, label, severity in _PAYLOAD_SIGNATURES:
            match = pattern.search(payload)
            if match:
                if self._should_alert(src_ip, label):
                    matched_text = match.group(0)[:120]  # cap for readability
                    try:
                        snippet = matched_text.decode("utf-8", errors="replace")
                    except Exception:
                        snippet = str(matched_text)
                    self.am.add_alert(
                        alert_type=label,
                        severity=severity,
                        source=src_ip,
                        description=f"Malicious payload detected in packet from {src_ip}: «{snippet}»",
                        details={
                            "pattern": label,
                            "matched": snippet,
                            "payload_length": len(payload),
                        },
                    )

    # ── Cool-down helper ──────────────────────────────────────────────────

    def _should_alert(self, source: str, label: str) -> bool:
        """Return True if we haven't alerted for this (source, label) recently."""
        key = (source, label)
        now = time.time()

        cooldown = (
            ARP_ALERT_COOLDOWN
            if "ARP" in label
            else PAYLOAD_ALERT_COOLDOWN
        )

        with self._cd_lock:
            last = self._cooldowns.get(key, 0)
            if now - last < cooldown:
                return False
            self._cooldowns[key] = now
            return True
