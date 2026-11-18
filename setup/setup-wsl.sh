#!/usr/bin/env bash
set -euo pipefail

CLAB_VERSION="0.82.0"
export DEBIAN_FRONTEND=noninteractive

if [[ "${EUID}" -eq 0 ]]; then
  SUDO=()
  TARGET_USER="${SUDO_USER:-root}"
else
  SUDO=(sudo)
  TARGET_USER="${USER}"
fi

if ! grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null; then
  echo "此脚本针对 WSL2；当前可能不在 WSL 中。" >&2
  read -r -p "仍然继续？[y/N] " answer
  [[ "$answer" =~ ^[Yy]$ ]] || exit 1
fi

echo "[1/3] 安装基础依赖"
"${SUDO[@]}" apt-get update -qq
"${SUDO[@]}" apt-get install -y -qq ca-certificates curl git python3 iproute2 iptables bash-completion

echo "[2/3] 检查 Docker"
if ! command -v docker >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    "${SUDO[@]}" apt-get install -y -qq docker.io
  else
    echo "未找到 docker，也无法使用 apt-get 自动安装。" >&2
    exit 1
  fi
fi

if ! docker info >/dev/null 2>&1; then
  if ! command -v dockerd >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
    echo "发现 Docker CLI 但没有本地 dockerd，安装 docker.io..."
    "${SUDO[@]}" apt-get install -y -qq docker.io
  fi
  if command -v dockerd >/dev/null 2>&1; then
    echo "启动本地 dockerd..."
    "${SUDO[@]}" nohup dockerd >/tmp/containerlab-dockerd.log 2>&1 &
    for _ in $(seq 1 30); do
      sleep 1
      docker info >/dev/null 2>&1 && break
    done
  fi
fi

if ! docker info >/dev/null 2>&1 && [[ -x /usr/bin/docker ]] && /usr/bin/docker info >/dev/null 2>&1; then
  "${SUDO[@]}" ln -sfn /usr/bin/docker /usr/local/bin/docker
fi

if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon 仍不可用。请启动 Docker Desktop 或在 WSL 中手动运行 sudo dockerd。" >&2
  exit 1
fi

"${SUDO[@]}" usermod -aG docker "${TARGET_USER}" || true

echo "[3/3] 安装 Containerlab v${CLAB_VERSION}"
if command -v containerlab >/dev/null 2>&1 && containerlab version 2>/dev/null | grep -q "${CLAB_VERSION}"; then
  echo "Containerlab v${CLAB_VERSION} 已安装"
else
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT
  asset="containerlab_${CLAB_VERSION}_linux_amd64.tar.gz"
  base="https://github.com/srl-labs/containerlab/releases/download/v${CLAB_VERSION}"
  curl -fsSL --retry 3 -o "$tmp_dir/$asset" "$base/$asset"
  curl -fsSL --retry 3 -o "$tmp_dir/checksums.txt" "$base/checksums.txt"
  (
    cd "$tmp_dir"
    grep "  $asset$" checksums.txt | sha256sum -c -
    tar -xzf "$asset"
    "${SUDO[@]}" install -m 0755 containerlab /usr/local/bin/containerlab
  )
fi

echo
echo "环境准备完成。当前 shell 若无法访问 Docker，请运行 newgrp docker 或重新打开 WSL。"
echo "随后执行：bash setup/preflight.sh"
