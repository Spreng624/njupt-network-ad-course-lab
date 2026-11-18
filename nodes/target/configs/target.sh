#!/usr/bin/env bash
set -euo pipefail
source /common/lib.sh

mkdir -p /run/sshd /run/lab /var/log
make_flag inject
make_flag scan
printf 'alice:%s\n' "$(openssl passwd -1 -salt labsalt victim123)" >/run/lab/hashes.txt
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj '/CN=app.intranet.lab' \
  -keyout /run/lab/target.key -out /run/lab/target.crt >/dev/null 2>&1

chmod 600 /run/lab/target.key
ssh-keygen -A >/dev/null
echo 'root:lab' | chpasswd

python3 /configs/target.py >/var/log/target-http.log 2>&1 &
exec /usr/sbin/sshd -D -e
