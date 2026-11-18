#!/usr/bin/env bash
set -euo pipefail

MIN_AVAILABLE_GB="${MIN_AVAILABLE_GB:-4}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail=0

ok() { printf '[ OK ] %s\n' "$*"; }
bad() { printf '[FAIL] %s\n' "$*" >&2; fail=1; }
info() { printf '[INFO] %s\n' "$*"; }

if grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null; then
  ok "检测到 WSL2 内核"
else
  info "当前不是 WSL2；脚本仍会检查 Linux/Docker 条件"
fi

if command -v docker >/dev/null 2>&1; then
  ok "Docker CLI: $(docker --version 2>/dev/null | head -1)"
  if docker info >/dev/null 2>&1; then
    ok "Docker daemon 可用"
  else
    bad "Docker daemon 未运行；启动 Docker Desktop 或本地 dockerd"
  fi
else
  bad "未找到 docker；先运行 bash setup/setup-wsl.sh"
fi

if command -v containerlab >/dev/null 2>&1; then
  clab_version="$(containerlab version 2>/dev/null | head -1 || true)"
  ok "Containerlab: ${clab_version:-已安装}"
else
  bad "未找到 containerlab；先运行 bash setup/setup-wsl.sh"
fi

if command -v python3 >/dev/null 2>&1; then
  ok "python3 可用"
else
  bad "未找到 python3"
fi

for tool in curl git ip iptables; do
  if command -v "$tool" >/dev/null 2>&1; then
    ok "$tool 可用"
  else
    bad "缺少 $tool"
  fi
done

mem_kb="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)"
mem_gb="$(awk -v kb="$mem_kb" 'BEGIN {printf "%.1f", kb/1048576}')"
if awk -v have="$mem_gb" -v need="$MIN_AVAILABLE_GB" 'BEGIN {exit !(have >= need)}'; then
  ok "可用内存 ${mem_gb} GiB（要求 ${MIN_AVAILABLE_GB} GiB）"
else
  bad "可用内存 ${mem_gb} GiB，低于要求的 ${MIN_AVAILABLE_GB} GiB"
fi

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
printf '\n环境预检通过。\n'
