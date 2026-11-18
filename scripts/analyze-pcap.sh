#!/usr/bin/env bash
set -euo pipefail

LAB="network-ad"
CONTAINER="clab-${LAB}-attacker"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $# -gt 0 ]]; then
  # 使用命令行指定的 pcap 文件
  PCAP="$1"
else
  # 默认选择 captures 目录中最近生成的 network pcap
  PCAP="$(
    find "$ROOT/captures" -maxdepth 1 -type f -name 'network-*.pcap' \
      -printf '%T@ %p\n' |
      sort -nr |
      head -1 |
      cut -d' ' -f2-
  )"
fi

if [[ -z "$PCAP" || ! -f "$PCAP" ]]; then
  echo "未找到 network pcap；先运行 bash scripts/capture.sh network 90" >&2
  exit 1
fi

CONTAINER_PCAP="/captures/$(basename "$PCAP")"

# 统计协议层次，确认抓包中包含 ARP、IP、TCP、TLS、DNS 和 ICMP
docker exec "$CONTAINER" tshark -r "$CONTAINER_PCAP" -q -z io,phs

# 列出课程要求重点观察的握手和探测报文
docker exec "$CONTAINER" tshark -r "$CONTAINER_PCAP" \
  -Y 'icmp or dns or tcp.flags.syn==1 or tls.handshake'
