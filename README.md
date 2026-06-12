# Network Packet Analyzer

A real-time CLI-based network packet capture and analysis tool built with Python and Scapy. Inspects live TCP/IP, UDP, and ICMP traffic at OSI layers 3–4, with protocol dissection, filterable output, GeoIP enrichment, and anomaly detection.

---

## Features

- **Live packet capture** using Scapy's `sniff()` with libpcap (Npcap on Windows)
- **Protocol dissection** — parses Ethernet frames, IP headers, and TCP/UDP/ICMP transport-layer fields
- **CLI filters** — filter captured traffic by protocol, source IP, or destination IP
- **GeoIP enrichment** — resolves source IPs to country and city using MaxMind GeoLite2
- **Anomaly detection** — flags SYN flood and port scan patterns in real time
- **Log to file** — saves all capture output to a `.txt` file
- **Capture summary** — prints packet counts by protocol on exit

---

## Screenshots

### SYN Flood Alert
![SYN Flood Alert](docs/syn_flood_alert.png)

### GeoIP Enriched Output
![GeoIP Output](docs/geoip_output.png)

---
## Requirements

- Python 3.8+
- [Npcap](https://npcap.com) (Windows) with WinPcap API compatibility mode enabled
- Dependencies:

```bash
pip install scapy colorama geoip2
```

- [GeoLite2-City.mmdb](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) — place in project root

---

## Usage

```bash
# Basic capture (run as Administrator)
python analyzing.py

# Filter by protocol
python analyzing.py --proto tcp

# Filter by source IP
python analyzing.py --src 192.168.1.6

# Filter by destination IP
python analyzing.py --dst 8.8.8.8

# Save output to file
python analyzing.py --output log.txt

# Auto-stop after N seconds
python analyzing.py --duration 30

# Combined
python analyzing.py --proto tcp --src 192.168.1.6 --output log.txt --duration 60
```

---

## Sample Output

```
[*] Capturing... Filters: proto=any | src=any | dst=any
[*] Anomaly detection: ON  (SYN flood + Port scan)
[*] Auto-stop in 60 seconds.

[03:47:12] TCP | 192.168.1.6 (LAN) -> 54.144.158.245 | Sport: 59248 -> Dport: 443 | Flags: PA
[03:47:12] TCP | 54.144.158.245 (US - Ashburn) -> 192.168.1.6 | Sport: 443 -> Dport: 59248 | Flags: A
[03:47:13] UDP | 192.168.1.8 (LAN) -> 224.0.0.251 | Sport: 5353 -> Dport: 5353

[!] ALERT | SYN FLOOD from 192.168.1.6 (LAN) | 15 SYNs in 5s

──────────────────────────────────────────────────
[*] CAPTURE SUMMARY
──────────────────────────────────────────────────
    TCP  packets : 854
    UDP  packets : 4
    ICMP packets : 0
    TOTAL        : 858

[*] Log saved to log.txt
[!] Capture stopped.
```

---

## Anomaly Detection

### SYN Flood Detection
Tracks SYN-only packets (`Flags: S`) per source IP within a 5-second sliding window. Fires an alert when a single IP sends 15+ SYNs within that window — indicative of a TCP SYN flood attack or aggressive connection retry behavior.

### Port Scan Detection
Tracks unique destination ports targeted per source IP. Fires an alert when a single IP contacts 10+ distinct ports — indicative of a port scan (e.g. nmap `-sS`).

Both detectors alert once per source IP per session to avoid log spam.

---

## Interesting Finding

During development, the tool consistently detected high volumes of unanswered SYN packets from the local machine (`192.168.1.6`) targeting the `103.165.192.x` subnet on port 443. These packets retried every few seconds with no SYN-ACK response, triggering the SYN flood detector automatically. Investigation revealed this subnet belongs to a background application repeatedly attempting HTTPS connections to an unreachable server — demonstrating the tool's ability to surface real anomalous behavior in normal traffic.

---

## Project Structure

```
Network Packet Analyser/
├── analyzing.py          # Main analyzer script
├── GeoLite2-City.mmdb    # MaxMind GeoIP database (not included, download separately)
├── log.txt               # Capture log (generated on run)
└── README.md
```

---

## Technical Notes

- Requires Administrator / root privileges for layer 2 packet capture
- GeoIP lookup fails gracefully — displays `(??)` for unresolved IPs and `(LAN)` for private ranges
- `--duration` uses Scapy's native `timeout` parameter for clean termination
