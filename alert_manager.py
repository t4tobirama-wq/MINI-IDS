"""
Alert Manager — Thread-safe alert storage, logging, and statistics tracking.
"""

import threading
import time
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# ─── Severity Levels ─────────────────────────────────────────────────────────

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

SEVERITY_COLORS = {
    SEVERITY_CRITICAL: Fore.RED + Style.BRIGHT,
    SEVERITY_HIGH: Fore.LIGHTRED_EX,
    SEVERITY_MEDIUM: Fore.YELLOW,
    SEVERITY_LOW: Fore.CYAN,
    SEVERITY_INFO: Fore.WHITE,
}


class AlertManager:
    """Stores alerts, prints to console, and exposes data for the dashboard."""

    def __init__(self, max_alerts: int = 5000):
        self._alerts: list[dict] = []
        self._lock = threading.Lock()
        self._max_alerts = max_alerts

        # Packet statistics
        self.stats = {
            "total_packets": 0,
            "arp_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "alerts_count": 0,
            "start_time": time.time(),
        }
        self._stats_lock = threading.Lock()

    # ── Alert creation ────────────────────────────────────────────────────

    def add_alert(
        self,
        alert_type: str,
        severity: str,
        source: str,
        description: str,
        details: dict | None = None,
    ):
        """Create and store a new alert."""
        alert = {
            "id": len(self._alerts) + 1,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "epoch": time.time(),
            "type": alert_type,
            "severity": severity,
            "source": source,
            "description": description,
            "details": details or {},
        }

        with self._lock:
            self._alerts.append(alert)
            # Trim oldest alerts if we exceed the limit
            if len(self._alerts) > self._max_alerts:
                self._alerts = self._alerts[-self._max_alerts:]

        with self._stats_lock:
            self.stats["alerts_count"] += 1

        self._print_alert(alert)
        return alert

    # ── Statistics ────────────────────────────────────────────────────────

    def increment_stat(self, key: str, amount: int = 1):
        with self._stats_lock:
            self.stats[key] = self.stats.get(key, 0) + amount

    def get_stats(self) -> dict:
        with self._stats_lock:
            s = dict(self.stats)
        s["uptime_seconds"] = int(time.time() - s["start_time"])
        s["unique_attackers"] = len({a["source"] for a in self.get_alerts()})
        return s

    # ── Queries ───────────────────────────────────────────────────────────

    def get_alerts(self, alert_type: str | None = None, limit: int | None = None) -> list[dict]:
        with self._lock:
            alerts = list(self._alerts)
        if alert_type:
            alerts = [a for a in alerts if a["type"] == alert_type]
        if limit:
            alerts = alerts[-limit:]
        return alerts

    # ── Console output ────────────────────────────────────────────────────

    @staticmethod
    def _print_alert(alert: dict):
        color = SEVERITY_COLORS.get(alert["severity"], Fore.WHITE)
        ts = alert["timestamp"]
        sev = alert["severity"]
        atype = alert["type"]
        src = alert["source"]
        desc = alert["description"]
        print(
            f"{Fore.LIGHTBLACK_EX}[{ts}] "
            f"{color}[{sev}] "
            f"{Fore.LIGHTWHITE_EX}[{atype}] "
            f"{Fore.MAGENTA}{src} "
            f"{Fore.WHITE}→ {desc}"
            f"{Style.RESET_ALL}"
        )
