#!/usr/bin/env python3
"""
Mini IDS — A lightweight Intrusion Detection System
====================================================
Sniffs live network packets with Scapy and detects:
  • ARP spoofing  (table conflicts, gratuitous ARP, ARP floods)
  • Malicious payloads (SQL injection, XSS, command injection,
    directory traversal, reverse shells)

Serves a real-time web dashboard on http://localhost:5000

Usage
-----
  python mini_ids.py                        # auto-detect interface
  python mini_ids.py --interface "Wi-Fi"    # specific interface
  python mini_ids.py --port 8080            # custom dashboard port

NOTE: Requires administrator / root privileges for raw-socket sniffing.
      On Windows, Npcap must be installed (https://npcap.com).
"""

import argparse
import sys
import logging

from colorama import Fore, Style, init as colorama_init


def banner():
    """Print the startup banner."""
    print(f"""
{Fore.CYAN}{Style.BRIGHT}
  ╔══════════════════════════════════════════════════════════╗
  ║                                                          ║
  ║     ███╗   ███╗██╗███╗   ██╗██╗    ██╗██████╗ ███████╗   ║
  ║     ████╗ ████║██║████╗  ██║██║    ██║██╔══██╗██╔════╝   ║
  ║     ██╔████╔██║██║██╔██╗ ██║██║    ██║██║  ██║███████╗   ║
  ║     ██║╚██╔╝██║██║██║╚██╗██║██║    ██║██║  ██║╚════██║   ║
  ║     ██║ ╚═╝ ██║██║██║ ╚████║██║    ██║██████╔╝███████║   ║
  ║     ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝    ╚═╝╚═════╝ ╚══════╝   ║
  ║                                                          ║
  ║   {Fore.WHITE}Intrusion Detection System{Fore.CYAN}                           ║
  ║   {Fore.LIGHTBLACK_EX}ARP Spoofing · Payload Scanning · Live Dashboard{Fore.CYAN}     ║
  ║                                                          ║
  ╚══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")


def main():
    colorama_init(autoreset=True)

    parser = argparse.ArgumentParser(
        description="Mini IDS — ARP Spoof & Payload Attack Detector"
    )
    parser.add_argument(
        "--interface", "-i",
        default=None,
        help="Network interface to sniff on (default: auto-detect)",
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=5000,
        help="Port for the web dashboard (default: 5000)",
    )
    args = parser.parse_args()

    banner()

    # Lazy imports so help text prints fast even without deps
    from alert_manager import AlertManager
    from detector import Detector
    from sniffer import Sniffer
    from dashboard import create_app

    # Wire everything together
    alert_mgr = AlertManager()
    detector  = Detector(alert_mgr)
    sniffer   = Sniffer(detector, iface=args.interface)

    # Start packet capture
    print(f"{Fore.YELLOW}[*] Starting packet sniffer "
          f"(interface: {args.interface or 'auto'})…{Style.RESET_ALL}")
    sniffer.start()
    print(f"{Fore.GREEN}[✓] Sniffer running.{Style.RESET_ALL}")

    # Start web dashboard
    print(f"{Fore.YELLOW}[*] Starting dashboard on "
          f"http://localhost:{args.port}{Style.RESET_ALL}")
    print(f"{Fore.LIGHTBLACK_EX}    Press Ctrl+C to stop.\n{Style.RESET_ALL}")

    # Suppress Flask's default request logs to keep console clean
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.WARNING)

    app = create_app(alert_mgr)
    try:
        app.run(host="0.0.0.0", port=args.port, debug=False)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Shutting down Mini IDS…{Style.RESET_ALL}")
        sys.exit(0)


if __name__ == "__main__":
    main()
