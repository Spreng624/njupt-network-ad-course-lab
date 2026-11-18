#!/usr/bin/env bash
set -euo pipefail

cat >/tmp/dnsmasq.conf <<'EOF'
port=53
bind-interfaces
no-resolv
no-hosts
log-queries
log-facility=-
address=/app.intranet.lab/10.30.50.10
address=/target.intranet.lab/10.30.50.10
address=/victim.intranet.lab/10.30.50.21
server=8.8.8.8
EOF

exec dnsmasq -k --conf-file=/tmp/dnsmasq.conf
