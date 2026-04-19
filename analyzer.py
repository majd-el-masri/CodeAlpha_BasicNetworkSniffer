#!/usr/bin/env python3
"""
analyzer.py — Offline packet analyzer for CodeAlpha Network Sniffer
Reads a JSON log produced by sniffer.py and generates a detailed report.
"""

import json
import sys
import argparse
from collections import Counter
from datetime import datetime

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("[!] colorama not installed. Run: pip install colorama")
    sys.exit(1)


def load_log(path: str) -> list:
    with open(path) as f:
        return json.load(f)


def print_section(title: str):
    print(f"\n{Fore.CYAN}{'─'*60}")
    print(f"  {Fore.YELLOW}{title}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─'*60}{Style.RESET_ALL}")


def bar(count: int, total: int, width: int = 30) -> str:
    filled = int(width * count / total) if total else 0
    pct    = 100 * count / total        if total else 0
    return f"{Fore.GREEN}{'█' * filled}{Fore.LIGHTBLACK_EX}{'░' * (width - filled)}{Style.RESET_ALL} {pct:5.1f}%"


def analyze(packets: list):
    total = len(packets)
    if total == 0:
        print(f"{Fore.RED}[!] Log file is empty.{Style.RESET_ALL}")
        return

    print(f"\n{Fore.WHITE}Total packets analyzed: {Fore.CYAN}{total}{Style.RESET_ALL}")

    # ── Protocol distribution ────────────────
    print_section("Protocol Distribution")
    proto_counts = Counter(p["protocol"] for p in packets)
    for proto, count in proto_counts.most_common():
        print(f"  {proto:<8} {count:>6}  {bar(count, total)}")

    # ── Top talkers (source IPs) ─────────────
    print_section("Top 10 Source IPs")
    src_counts = Counter(p["src"] for p in packets if p["src"] != "?")
    for ip, count in src_counts.most_common(10):
        print(f"  {Fore.WHITE}{ip:<20}{Style.RESET_ALL}  {count:>5}  {bar(count, total)}")

    # ── Top destination IPs ──────────────────
    print_section("Top 10 Destination IPs")
    dst_counts = Counter(p["dst"] for p in packets if p["dst"] != "?")
    for ip, count in dst_counts.most_common(10):
        print(f"  {Fore.WHITE}{ip:<20}{Style.RESET_ALL}  {count:>5}  {bar(count, total)}")

    # ── DNS queries ──────────────────────────
    dns_pkts = [p for p in packets if p["protocol"] == "DNS"]
    if dns_pkts:
        print_section(f"DNS Queries ({len(dns_pkts)} total)")
        dns_domains = Counter(p["info"].replace("Query: ", "") for p in dns_pkts)
        for domain, count in dns_domains.most_common(10):
            print(f"  {Fore.CYAN}{domain:<40}{Style.RESET_ALL}  ×{count}")

    # ── HTTP requests ────────────────────────
    http_pkts = [p for p in packets if p["protocol"] == "HTTP"]
    if http_pkts:
        print_section(f"HTTP Requests ({len(http_pkts)} total)")
        for p in http_pkts[:15]:
            print(f"  {Fore.RED}{p['src']:<18}{Style.RESET_ALL} → {p['info']}")

    # ── Timeline (per-second rate) ───────────
    print_section("Capture Timeline (packets per second)")
    ts_counts: Counter = Counter()
    for p in packets:
        second = p["timestamp"][:8]   # HH:MM:SS
        ts_counts[second] += 1
    max_count = max(ts_counts.values()) if ts_counts else 1
    for ts in sorted(ts_counts)[-20:]:   # last 20 seconds
        cnt = ts_counts[ts]
        b   = int(50 * cnt / max_count)
        print(f"  {ts}  {Fore.GREEN}{'█' * b}{Style.RESET_ALL}  {cnt}")

    print(f"\n{Fore.GREEN}[✔] Analysis complete.{Style.RESET_ALL}\n")


def main():
    p = argparse.ArgumentParser(description="CodeAlpha — Offline Packet Analyzer")
    p.add_argument("log", help="Path to JSON log from sniffer.py")
    args = p.parse_args()
    packets = load_log(args.log)
    analyze(packets)


if __name__ == "__main__":
    main()
