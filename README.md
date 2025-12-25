# Network MITM attack detector

A minimal network-based intrusion detection prototype designed to detect common man in the middle (MITM) attacks in home and small LAN environments.

This project passively monitors network traffic using `libpcap` and detects suspicious behavior related to:
- ARP poisoning
- Gateway impersonation
- Rogue DNS servers
- Rogue DHCP servers

The detector relies on behavioral consistency and trusted gateway identification rather than signature databases.

It is *not* designed for enterprise networks, VPNs, or environments with multiple legitimate gateways. It is a proof of concept of how one may detect network attacks on their machine in simple LAN.

## How It Works

1. Automatically selects a network interface using `pcap_lookupdev`
2. Reads the default gateway IP from `/proc/net/route`
3. Passively captures Ethernet frames using `libpcap`
4. Parses:
   - Ethernet
   - ARP
   - IPv4
   - UDP
5. Correlates MAC addresses, IP addresses, ports, and TTL values
6. Generates alerts when suspicious inconsistencies are detected


## Requirements

- Linux (uses `/proc/net/route`)
- `libpcap`
- Root privileges (required for packet capture)


## Build & Run

```bash
gcc detector.c -o detector -lpcap
sudo ./detector
