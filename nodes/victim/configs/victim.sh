#!/usr/bin/env bash
set -euo pipefail
source /common/lib.sh

mkdir -p /run/sshd /run/lab /var/log
make_flag hydra
make_flag detect
adduser -D -s /bin/sh alice 2>/dev/null || true
echo 'alice:victim123' | chpasswd
echo 'root:lab' | chpasswd
install -d -m 0700 -o alice -g alice /home/alice/.ssh
printf 'FLAG_SSH=%s\n' "$(cat /run/lab/hydra.flag)" >/home/alice/.ssh/environment
chown alice:alice /home/alice/.ssh/environment
chmod 0600 /home/alice/.ssh/environment
ssh-keygen -A >/dev/null
cat >/etc/ssh/sshd_config.d/lab.conf <<'EOF'
PasswordAuthentication yes
PermitRootLogin yes
PermitUserEnvironment yes
UsePAM no
EOF

printf 'nameserver 10.30.50.53\noptions attempts:1 timeout:1\n' >/etc/resolv.conf
python3 /configs/client.py >/var/log/victim-traffic.log 2>&1 &
nohup sniff-detector -i "$(data_if)" >/var/log/sniff-detector.log 2>&1 &
exec /usr/sbin/sshd -D -e
