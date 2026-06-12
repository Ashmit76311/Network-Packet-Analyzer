import signal
signal.signal(signal.SIGINT, signal.default_int_handler)

from scapy.all import sniff, IP, TCP, UDP, ICMP
from colorama import Fore, init
from datetime import datetime
from collections import defaultdict
import argparse
import time
import geoip2.database

init(autoreset=True)

# ─────────────────────────────────────────
# GEOIP SETUP
# ─────────────────────────────────────────
try:
    geo_reader = geoip2.database.Reader("GeoLite2-City.mmdb")
except FileNotFoundError:
    geo_reader = None
    print(f"{Fore.YELLOW}[!] GeoLite2-City.mmdb not found. GeoIP disabled.")

def get_geo(ip):
    if not geo_reader:
        return ""
    try:
        r = geo_reader.city(ip)
        country = r.country.iso_code or "??"
        city    = r.city.name or ""
        return f" ({country}{' - ' + city if city else ''})"
    except Exception:
        return " (LAN)"

# ─────────────────────────────────────────
# CLI ARGUMENTS
# ─────────────────────────────────────────
parser = argparse.ArgumentParser(description="Network Packet Analyzer")
parser.add_argument("--proto",    help="Filter by protocol: tcp / udp / icmp")
parser.add_argument("--src",      help="Filter by source IP")
parser.add_argument("--dst",      help="Filter by destination IP")
parser.add_argument("--output",   help="Save output to file e.g. log.txt")
parser.add_argument("--duration", help="Stop after N seconds e.g. 15", type=int)
args = parser.parse_args()

# ─────────────────────────────────────────
# PACKET COUNTER
# ─────────────────────────────────────────
packet_count = {"tcp": 0, "udp": 0, "icmp": 0, "total": 0}

# ─────────────────────────────────────────
# ANOMALY TRACKING STATE
# ─────────────────────────────────────────
syn_tracker  = defaultdict(list)
port_tracker = defaultdict(set)

SYN_THRESHOLD  = 15
PORT_THRESHOLD = 10
TIME_WINDOW    = 5

alerted_syn   = set()
alerted_ports = set()

# ─────────────────────────────────────────
# LOG FUNCTION
# ─────────────────────────────────────────
def log(msg):
    print(msg)
    if args.output:
        with open(args.output, "a") as f:
            f.write(msg + "\n")

# ─────────────────────────────────────────
# ANOMALY DETECTORS
# ─────────────────────────────────────────
def detect_syn_flood(src, now):
    syn_tracker[src].append(now)
    syn_tracker[src] = [t for t in syn_tracker[src] if now - t < TIME_WINDOW]

    if len(syn_tracker[src]) >= SYN_THRESHOLD and src not in alerted_syn:
        alerted_syn.add(src)
        log(
            f"{Fore.RED}[!] ALERT | SYN FLOOD from {src}{get_geo(src)} | "
            f"{len(syn_tracker[src])} SYNs in {TIME_WINDOW}s"
        )

def detect_port_scan(src, dport):
    port_tracker[src].add(dport)

    if len(port_tracker[src]) >= PORT_THRESHOLD and src not in alerted_ports:
        alerted_ports.add(src)
        log(
            f"{Fore.RED}[!] ALERT | PORT SCAN from {src}{get_geo(src)} | "
            f"{len(port_tracker[src])} unique ports targeted"
        )

# ─────────────────────────────────────────
# PACKET HANDLER
# ─────────────────────────────────────────
def handle_packet(packet):
    if not packet.haslayer(IP):
        return

    ip    = packet[IP]
    src   = ip.src
    dst   = ip.dst
    proto = None
    info  = ""
    now   = time.time()

    if packet.haslayer(TCP):
        proto = "tcp"
        tcp   = packet[TCP]
        info  = f"Sport: {tcp.sport} -> Dport: {tcp.dport} | Flags: {tcp.flags}"
        color = Fore.CYAN
        if str(tcp.flags) == "S":
            detect_syn_flood(src, now)
        detect_port_scan(src, tcp.dport)

    elif packet.haslayer(UDP):
        proto = "udp"
        udp   = packet[UDP]
        info  = f"Sport: {udp.sport} -> Dport: {udp.dport}"
        color = Fore.YELLOW

    elif packet.haslayer(ICMP):
        proto = "icmp"
        info  = f"Type: {packet[ICMP].type}"
        color = Fore.MAGENTA
    else:
        return

    if args.proto and args.proto.lower() != proto:
        return
    if args.src and args.src != src:
        return
    if args.dst and args.dst != dst:
        return

    packet_count["total"] += 1
    packet_count[proto]   += 1

    timestamp = datetime.now().strftime("%H:%M:%S")
    log(
        f"{color}[{timestamp}] {proto.upper()} | "
        f"{src}{get_geo(src)} -> {dst} | {info}"
    )

# ─────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────
def print_summary():
    print(f"\n{Fore.YELLOW}{'─'*50}")
    print(f"{Fore.YELLOW}[*] CAPTURE SUMMARY")
    print(f"{Fore.YELLOW}{'─'*50}")
    print(f"    TCP  packets : {packet_count['tcp']}")
    print(f"    UDP  packets : {packet_count['udp']}")
    print(f"    ICMP packets : {packet_count['icmp']}")
    print(f"    TOTAL        : {packet_count['total']}")
    if args.output:
        print(f"\n{Fore.GREEN}[*] Log saved to {args.output}")
    print(f"{Fore.RED}[!] Capture stopped.")

# ─────────────────────────────────────────
# START CAPTURE
# ─────────────────────────────────────────
filter_summary = f"proto={args.proto or 'any'} | src={args.src or 'any'} | dst={args.dst or 'any'}"
print(f"{Fore.GREEN}[*] Capturing... Filters: {filter_summary}")
print(f"{Fore.GREEN}[*] Anomaly detection: ON  (SYN flood + Port scan)")
if args.duration:
    print(f"{Fore.GREEN}[*] Auto-stop in {args.duration} seconds.\n")
else:
    print(f"{Fore.GREEN}[*] Press Ctrl+C to stop.\n")

sniff(prn=handle_packet, store=False, timeout=args.duration)
print_summary()