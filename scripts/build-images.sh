#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

build_args=()
if [[ -n "${DOCKER_BUILD_PROXY:-}" ]]; then
  build_args+=(
    --build-arg "HTTP_PROXY=$DOCKER_BUILD_PROXY"
    --build-arg "HTTPS_PROXY=$DOCKER_BUILD_PROXY"
    --build-arg "http_proxy=$DOCKER_BUILD_PROXY"
    --build-arg "https_proxy=$DOCKER_BUILD_PROXY"
    --build-arg "NO_PROXY=${NO_PROXY:-localhost,127.0.0.1,10.30.50.0/24}"
  )
fi

for node in target victim dns gateway attacker; do
  docker build "${build_args[@]}" -t "network-ad/${node}:latest" "nodes/${node}"
done
