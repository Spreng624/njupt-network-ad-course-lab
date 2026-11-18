#!/usr/bin/env bash
set -euo pipefail

INTERFACE="${MASSCAN_INTERFACE:-eth1}"
GATEWAY_IP="${MASSCAN_GATEWAY_IP:-10.30.50.254}"
TARGET="${1:-10.30.50.0/24}"
PORTS="${2:-22,80,443}"
RATE="${3:-500}"

[[ "$RATE" =~ ^[1-9][0-9]*$ ]] || {
  echo "扫描速率必须是正整数" >&2
  exit 1
}

# 先填充网关邻居表，避免 masscan 把默认路由误判为 0.0.0.0
ping -c 1 -W 1 "$GATEWAY_IP" >/dev/null 2>&1 || true

# 从当前攻击机的邻居表读取网关 MAC
ROUTER_MAC="$(
  ip neigh show "$GATEWAY_IP" |
    awk '/lladdr/ {print $5; exit}'
)"
if [[ -z "$ROUTER_MAC" ]]; then
  echo "无法解析网关 $GATEWAY_IP 的 MAC 地址" >&2
  exit 1
fi

echo "interface=$INTERFACE gateway=$GATEWAY_IP router_mac=$ROUTER_MAC"

# 直接在攻击机内部执行 masscan
exec masscan "$TARGET" \
  -p"$PORTS" \
  --interface "$INTERFACE" \
  --router-ip "$GATEWAY_IP" \
  --router-mac "$ROUTER_MAC" \
  --rate "$RATE" \
  --wait 2
