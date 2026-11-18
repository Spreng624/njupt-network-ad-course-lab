#!/usr/bin/env bash
set -euo pipefail

: "${LAB_IP:?LAB_IP is required}"
LAB_IF="${LAB_IF:-eth1}"
LAB_PREFIX="${LAB_PREFIX:-24}"
LAB_SKIP_IP="${LAB_SKIP_IP:-0}"

for _ in $(seq 1 90); do
  if ip link show dev "$LAB_IF" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! ip link show dev "$LAB_IF" >/dev/null 2>&1; then
  echo "数据接口 ${LAB_IF} 未创建" >&2
  exit 1
fi

ip link set dev "$LAB_IF" up
if [[ "$LAB_SKIP_IP" != "1" ]]; then
  if ! ip -o -4 addr show dev "$LAB_IF" | awk -v ip="$LAB_IP" '$4 ~ "^"ip"/" {found=1} END {exit !found}'; then
    ip addr add "${LAB_IP}/${LAB_PREFIX}" dev "$LAB_IF"
  fi
  if ! ip -o -4 addr show dev "$LAB_IF" | awk -v ip="$LAB_IP" '$4 ~ "^"ip"/" {found=1} END {exit !found}'; then
    echo "数据接口 ${LAB_IF} 未获得 ${LAB_IP}" >&2
    exit 1
  fi
fi

exec "$@"
