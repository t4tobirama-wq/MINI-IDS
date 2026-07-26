"""
Sniffer — Captures live network packets using Scapy and feeds them to the Detector.
"""

import threading
from scapy.all import sniff, conf

from detector import Detector


class Sniffer:
    """Runs Scapy's sniff() in a daemon thread."""

    def __init__(self, detector: Detector, iface: str | None = None):
        self.detector = detector
        self.iface = iface
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start sniffing in a background daemon thread."""
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        """Internal — runs the Scapy sniffer."""
        # On Windows, Scapy uses Npcap by default
        sniff_kwargs = {
            "prn": self._on_packet,
            "store": False,
            # Capture ARP + IP traffic (TCP/UDP payloads ride on IP)
            "filter": "arp or ip",
        }
        if self.iface:
            sniff_kwargs["iface"] = self.iface

        sniff(**sniff_kwargs)

    def _on_packet(self, packet) -> None:
        """Callback for every captured packet — delegates to the detector."""
        try:
            self.detector.analyse(packet)
        except Exception as exc:
            # Never let a single bad packet crash the sniffer
            pass
