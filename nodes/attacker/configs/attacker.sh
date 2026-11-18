#!/usr/bin/env bash
set -euo pipefail

printf '10.30.50.10 app.intranet.lab target.intranet.lab\n' >>/etc/hosts
sysctl -w net.ipv4.ip_forward=1 >/dev/null
mkdir -p /captures /tmp/lab

cat <<'BANNER'
==============================================================
 network-ad attacker
 target   10.30.50.10
 victim   10.30.50.21
 dns      10.30.50.53
 gateway  10.30.50.254
==============================================================
 tools: nmap rustscan masscan arp-scan tshark tcpdump hydra john nikto scapy
BANNER
exec tail -f /dev/null
