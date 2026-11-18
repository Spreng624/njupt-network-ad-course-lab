#!/usr/bin/env bash
set -euo pipefail

ip link add br0 type bridge 2>/dev/null || true
for IF in eth1 eth2 eth3 eth4; do
  ip link set "$IF" master br0
  ip link set "$IF" up
done
ip addr replace 10.30.50.254/24 dev br0
ip link set br0 up
sysctl -w net.ipv4.ip_forward=1 >/dev/null
echo "gateway ready on br0; ip_forward=1"
exec tail -f /dev/null
