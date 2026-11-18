#!/usr/bin/env bash

data_if() {
  ip -o -4 addr show | awk -v ip="${LAB_IP}" '$4 ~ "^"ip"/" {print $2; exit}'
}

make_flag() {
  local name="$1"
  local path="/run/lab/${name}.flag"
  mkdir -p /run/lab
  if [[ ! -s "$path" ]]; then
    printf 'flag{%s}\n' "$(cat /proc/sys/kernel/random/uuid)" >"$path"
  fi
}

wait_port() {
  local host="$1"
  local port="$2"
  local timeout="${3:-60}"
  for _ in $(seq 1 "$timeout"); do
    if (echo >"/dev/tcp/$host/$port") >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}
