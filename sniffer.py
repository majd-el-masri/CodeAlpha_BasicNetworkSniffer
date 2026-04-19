#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║        CodeAlpha — Basic Network Sniffer             ║
║        Task 1 | Cybersecurity Internship             ║
╚══════════════════════════════════════════════════════╝

Author  : [Your Name]
Program : CodeAlpha Cybersecurity Internship
Purpose : Capture and analyze network packets in real time
"""

import sys
import os
import time
import argparse
import signal
import json
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, Ether, ARP
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    print("[!] Scapy is not installed. Run: pip install scapy")
    sys.exit(1)

try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
except ImportError:
    print("[!] colorama not installed. Run: pip install colorama")
    sys.exit(1)


# ──────────────────────────────────────────────
# Globals & Stats
# ──────────────────────────────────────────────
stats = {
    "total":   0,
    "tcp":     0,
    "udp":     0,
    "icmp":    0,
    "arp":     0,
    "dns":     0,
    "http":    0,
    "other":   0,
    "start":   time.time(),
}

packet_log = []   # stores dicts for optional JSON export
DIVIDER     = Fore.CYAN + "─" * 70 + Style.RESET_ALL


# ──────────────────────────────────────────────
# Banner
# ──────────────────────────────────────────────
def print_banner():
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║   {Fore.YELLOW}  ██████╗ ███╗   ██╗██╗███████╗███████╗███████╗██████╗           {Fore.CYAN}║
║   {Fore.YELLOW} ██╔════╝ ████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗          {Fore.CYAN}║
║   {Fore.YELLOW} ╚█████╗  ██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝          {Fore.CYAN}║
║   {Fore.YELLOW}  ╚═══██╗ ██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗          {Fore.CYAN}║
║   {Fore.YELLOW} ██████╔╝ ██║ ╚████║██║██║     ██║     ███████╗██║  ██║          {Fore.CYAN}║
║   {Fore.YELLOW} ╚═════╝  ╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝          {Fore.CYAN}║
║                                                                      ║
║   {Fore.GREEN}Basic Network Sniffer  •  CodeAlpha Internship  •  Task 1        {Fore.CYAN}║
╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────
def timestamp():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def protocol_tag(proto: str) -> str:
    colors = {
        "TCP":   Fore.GREEN,
        "UDP":   Fore.BLUE,
        "ICMP":  Fore.YELLOW,
        "ARP":   Fore.MAGENTA,
        "DNS":   Fore.CYAN,
        "HTTP":  Fore.RED,
        "OTHER": Fore.WHITE,
    }
    c = colors.get(proto, Fore.WHITE)
    return f"{c}[{proto:>5}]{Style.RESET_ALL}"


def flag_str(tcp_flags) -> str:
    """Convert numeric/string TCP flags to readable format."""
    mapping = {0x01: "FIN", 0x02: "SYN", 0x04: "RST",
                0x08: "PSH", 0x10: "ACK", 0x20: "URG"}
    try:
        flags_int = int(tcp_flags)
        active = [v for k, v in mapping.items() if flags_int & k]
        return "|".join(active) if active else str(tcp_flags)
    except Exception:
        return str(tcp_flags)


# ──────────────────────────────────────────────
# Packet Processor
# ──────────────────────────────────────────────
def process_packet(packet, args):
    stats["total"] += 1
    record = {
        "timestamp": timestamp(),
        "number":    stats["total"],
        "protocol":  "OTHER",
        "src":       "?",
        "dst":       "?",
        "info":      "",
    }

    # ── ARP ──────────────────────────────────
    if packet.haslayer(ARP):
        stats["arp"] += 1
        record["protocol"] = "ARP"
        arp = packet[ARP]
        record["src"] = arp.psrc
        record["dst"] = arp.pdst
        op  = "Request" if arp.op == 1 else "Reply"
        record["info"] = f"{op}  {arp.hwsrc} → {arp.hwdst}"
        line = (
            f"{Fore.CYAN}{record['timestamp']}{Style.RESET_ALL}  "
            f"#{record['number']:<5} "
            f"{protocol_tag('ARP')}  "
            f"{Fore.WHITE}{record['src']:<18}{Style.RESET_ALL} → "
            f"{Fore.WHITE}{record['dst']:<18}{Style.RESET_ALL}  "
            f"{Fore.MAGENTA}{record['info']}{Style.RESET_ALL}"
        )

    # ── IP-based ─────────────────────────────
    elif packet.haslayer(IP):
        ip = packet[IP]
        record["src"] = ip.src
        record["dst"] = ip.dst

        # HTTP
        if packet.haslayer(HTTPRequest):
            stats["http"] += 1
            record["protocol"] = "HTTP"
            http = packet[HTTPRequest]
            method = http.Method.decode() if http.Method else "?"
            host   = http.Host.decode()   if http.Host   else "?"
            path   = http.Path.decode()   if http.Path   else "/"
            record["info"] = f"{method} {host}{path}"
            line = (
                f"{Fore.CYAN}{record['timestamp']}{Style.RESET_ALL}  "
                f"#{record['number']:<5} "
                f"{protocol_tag('HTTP')}  "
                f"{Fore.WHITE}{ip.src:<18}{Style.RESET_ALL} → "
                f"{Fore.WHITE}{ip.dst:<18}{Style.RESET_ALL}  "
                f"{Fore.RED}{record['info']}{Style.RESET_ALL}"
            )

        # DNS
        elif packet.haslayer(DNS) and packet.haslayer(DNSQR):
            stats["dns"] += 1
            record["protocol"] = "DNS"
            qname = packet[DNSQR].qname.decode(errors="replace").rstrip(".")
            record["info"] = f"Query: {qname}"
            line = (
                f"{Fore.CYAN}{record['timestamp']}{Style.RESET_ALL}  "
                f"#{record['number']:<5} "
                f"{protocol_tag('DNS')}  "
                f"{Fore.WHITE}{ip.src:<18}{Style.RESET_ALL} → "
                f"{Fore.WHITE}{ip.dst:<18}{Style.RESET_ALL}  "
                f"{Fore.CYAN}{record['info']}{Style.RESET_ALL}"
            )

        # ICMP
        elif packet.haslayer(ICMP):
            stats["icmp"] += 1
            record["protocol"] = "ICMP"
            icmp_type = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreach"}.get(
                packet[ICMP].type, f"Type {packet[ICMP].type}"
            )
            record["info"] = icmp_type
            line = (
                f"{Fore.CYAN}{record['timestamp']}{Style.RESET_ALL}  "
                f"#{record['number']:<5} "
                f"{protocol_tag('ICMP')}  "
                f"{Fore.WHITE}{ip.src:<18}{Style.RESET_ALL} → "
                f"{Fore.WHITE}{ip.dst:<18}{Style.RESET_ALL}  "
                f"{Fore.YELLOW}{record['info']}{Style.RESET_ALL}"
            )

        # TCP
        elif packet.haslayer(TCP):
            stats["tcp"] += 1
            record["protocol"] = "TCP"
            tcp = packet[TCP]
            flags = flag_str(tcp.flags)
            record["info"] = f"Port {tcp.sport} → {tcp.dport}  [{flags}]"
            payload_preview = ""
            if args.payload and packet.haslayer(Raw):
                raw = packet[Raw].load
                preview = raw[:60].decode(errors="replace").replace("\n", "")
                payload_preview = f"  {Fore.LIGHTBLACK_EX}│ {preview}{Style.RESET_ALL}"
            line = (
                f"{Fore.CYAN}{record['timestamp']}{Style.RESET_ALL}  "
                f"#{record['number']:<5} "
                f"{protocol_tag('TCP')}  "
                f"{Fore.WHITE}{ip.src:<18}{Style.RESET_ALL} → "
                f"{Fore.WHITE}{ip.dst:<18}{Style.RESET_ALL}  "
                f"{Fore.GREEN}{record['info']}{Style.RESET_ALL}"
                f"{payload_preview}"
            )

        # UDP
        elif packet.haslayer(UDP):
            stats["udp"] += 1
            record["protocol"] = "UDP"
            udp = packet[UDP]
            record["info"] = f"Port {udp.sport} → {udp.dport}  Len={udp.len}"
            line = (
                f"{Fore.CYAN}{record['timestamp']}{Style.RESET_ALL}  "
                f"#{record['number']:<5} "
                f"{protocol_tag('UDP')}  "
                f"{Fore.WHITE}{ip.src:<18}{Style.RESET_ALL} → "
                f"{Fore.WHITE}{ip.dst:<18}{Style.RESET_ALL}  "
                f"{Fore.BLUE}{record['info']}{Style.RESET_ALL}"
            )

        else:
            stats["other"] += 1
            record["info"] = f"Proto={ip.proto}"
            line = (
                f"{Fore.CYAN}{record['timestamp']}{Style.RESET_ALL}  "
                f"#{record['number']:<5} "
                f"{protocol_tag('OTHER')}  "
                f"{Fore.WHITE}{ip.src:<18}{Style.RESET_ALL} → "
                f"{Fore.WHITE}{ip.dst:<18}{Style.RESET_ALL}  "
                f"{record['info']}"
            )
    else:
        stats["other"] += 1
        line = (
            f"{Fore.CYAN}{record['timestamp']}{Style.RESET_ALL}  "
            f"#{record['number']:<5} "
            f"{protocol_tag('OTHER')}  "
            f"{'Non-IP frame':^40}"
        )

    # ── Apply filters ────────────────────────
    if args.filter_proto and record["protocol"] not in [p.upper() for p in args.filter_proto]:
        return
    if args.filter_ip and args.filter_ip not in (record["src"], record["dst"]):
        return
    if args.filter_port:
        port_str = str(args.filter_port)
        if port_str not in record["info"]:
            return

    print(line)
    packet_log.append(record)

    # Live stats every 50 packets
    if args.live_stats and stats["total"] % 50 == 0:
        print_stats()


# ──────────────────────────────────────────────
# Stats Summary
# ──────────────────────────────────────────────
def print_stats():
    elapsed = time.time() - stats["start"]
    rate    = stats["total"] / elapsed if elapsed > 0 else 0
    print(f"\n{DIVIDER}")
    print(
        f"  {Fore.YELLOW}📊 Live Stats{Style.RESET_ALL}  "
        f"Total: {Fore.WHITE}{stats['total']}{Style.RESET_ALL}  │  "
        f"TCP: {Fore.GREEN}{stats['tcp']}{Style.RESET_ALL}  "
        f"UDP: {Fore.BLUE}{stats['udp']}{Style.RESET_ALL}  "
        f"ICMP: {Fore.YELLOW}{stats['icmp']}{Style.RESET_ALL}  "
        f"DNS: {Fore.CYAN}{stats['dns']}{Style.RESET_ALL}  "
        f"HTTP: {Fore.RED}{stats['http']}{Style.RESET_ALL}  "
        f"ARP: {Fore.MAGENTA}{stats['arp']}{Style.RESET_ALL}  │  "
        f"Rate: {Fore.WHITE}{rate:.1f} pkt/s{Style.RESET_ALL}"
    )
    print(DIVIDER + "\n")


def print_final_summary(output_file=None):
    elapsed = time.time() - stats["start"]
    rate    = stats["total"] / elapsed if elapsed > 0 else 0
    print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════╗")
    print(f"║         📊  CAPTURE SUMMARY                     ║")
    print(f"╠══════════════════════════════════════════════════╣{Style.RESET_ALL}")
    rows = [
        ("Total Packets",  stats["total"],  Fore.WHITE),
        ("TCP",            stats["tcp"],    Fore.GREEN),
        ("UDP",            stats["udp"],    Fore.BLUE),
        ("ICMP",           stats["icmp"],   Fore.YELLOW),
        ("DNS",            stats["dns"],    Fore.CYAN),
        ("HTTP",           stats["http"],   Fore.RED),
        ("ARP",            stats["arp"],    Fore.MAGENTA),
        ("Other",          stats["other"],  Fore.WHITE),
        ("Duration (s)",   f"{elapsed:.2f}", Fore.WHITE),
        ("Avg Rate",       f"{rate:.1f} pkt/s", Fore.WHITE),
    ]
    for label, val, color in rows:
        print(f"{Fore.CYAN}║{Style.RESET_ALL}  {label:<20} {color}{val}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╚══════════════════════════════════════════════════╝{Style.RESET_ALL}")
    if output_file:
        with open(output_file, "w") as f:
            json.dump(packet_log, f, indent=2)
        print(f"\n{Fore.GREEN}[✔] Packet log saved → {output_file}{Style.RESET_ALL}")


# ──────────────────────────────────────────────
# Argument Parser
# ──────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        description="CodeAlpha — Basic Network Sniffer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python sniffer.py                          # Capture all on default iface
  sudo python sniffer.py -i eth0 -c 100          # 100 packets on eth0
  sudo python sniffer.py --filter-proto TCP DNS  # Show only TCP and DNS
  sudo python sniffer.py --filter-ip 192.168.1.1 # Filter by IP
  sudo python sniffer.py --payload -o log.json   # Show payload + save JSON
        """,
    )
    p.add_argument("-i", "--iface",        default=None,   help="Network interface (default: auto)")
    p.add_argument("-c", "--count",        type=int, default=0, help="Number of packets (0 = infinite)")
    p.add_argument("--filter-proto",       nargs="+",      help="Filter by protocol: TCP UDP ICMP DNS HTTP ARP")
    p.add_argument("--filter-ip",          default=None,   help="Filter by IP address (src or dst)")
    p.add_argument("--filter-port",        type=int,       help="Filter by port number")
    p.add_argument("--payload",            action="store_true", help="Show raw payload preview for TCP")
    p.add_argument("--live-stats",         action="store_true", help="Print stats every 50 packets")
    p.add_argument("-o", "--output",       default=None,   help="Save captured packets to JSON file")
    return p


# ──────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────
def main():
    parser = build_parser()
    args   = parser.parse_args()

    # Check admin privileges (Windows & Linux compatible)
    import platform, ctypes
    if platform.system() == "Windows":
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        is_admin = os.geteuid() == 0
    if not is_admin:
        print(f"{Fore.RED}[!] Administrator privileges required.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    → Close VS Code, right-click it, and choose 'Run as administrator'{Style.RESET_ALL}")
        sys.exit(1)

    print_banner()

    # Column header
    print(f"{Fore.CYAN}{'Timestamp':<15} {'#':<6} {'Proto':>7}  {'Source':<20} {'Destination':<20} {'Info'}{Style.RESET_ALL}")
    print(DIVIDER)

    def _sigint(sig, frame):
        print(f"\n{Fore.YELLOW}[!] Interrupted by user.{Style.RESET_ALL}")
        print_final_summary(args.output)
        sys.exit(0)

    signal.signal(signal.SIGINT, _sigint)

    print(f"{Fore.GREEN}[*] Sniffing on interface: {args.iface or 'auto'} | Count: {args.count or '∞'}{Style.RESET_ALL}\n")

    sniff(
        iface=args.iface,
        count=args.count,
        prn=lambda pkt: process_packet(pkt, args),
        store=False,
    )

    print_final_summary(args.output)


if __name__ == "__main__":
    main()
