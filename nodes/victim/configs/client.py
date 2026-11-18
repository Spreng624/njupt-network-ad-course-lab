#!/usr/bin/env python3
import http.client
import socket
import ssl
import subprocess
import time
import urllib.parse


APP = "app.intranet.lab"
TARGET = "10.30.50.10"


def log(message):
    print(time.strftime("%Y-%m-%dT%H:%M:%S"), message, flush=True)


def request(path, cookie=""):
    conn = http.client.HTTPConnection(APP, 80, timeout=3)
    headers = {"User-Agent": "lab-victim"}
    if cookie:
        headers["Cookie"] = f"session={cookie}"
    conn.request("GET", path, headers=headers)
    response = conn.getresponse()
    body = response.read().decode("utf-8", "replace")
    cookie = response.getheader("Set-Cookie", "")
    conn.close()
    return response.status, body, cookie


def ping(host):
    return subprocess.run(
        ["ping", "-c", "1", "-W", "1", host],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0


def main():
    session = ""
    cycle = 0
    while True:
        cycle += 1
        try:
            ip = socket.gethostbyname(APP)
            log(f"cycle={cycle} dns={APP}:{ip}")
        except OSError as exc:
            log(f"cycle={cycle} dns failure: {exc}")
            time.sleep(5)
            continue

        try:
            status, body, set_cookie = request("/login?user=alice&pass=victim123")
            log(f"login status={status} body={body.strip()!r}")
            for part in set_cookie.split(";"):
                key, _, value = part.strip().partition("=")
                if key == "session":
                    session = value
            if session:
                path = "/api/transfer?account=acct-1&amount=1"
                status, body, _ = request(path, session)
                log(f"transfer status={status} body={body.strip()!r} cookie={session}")
        except OSError as exc:
            log(f"http failure: {exc}")
            session = ""

        log(f"ping target ok={ping(TARGET)} failed-target ok={ping('10.30.50.250')}")
        try:
            context = ssl._create_unverified_context()
            with socket.create_connection((TARGET, 443), timeout=2) as raw:
                with context.wrap_socket(raw, server_hostname=APP):
                    log("tls handshake complete")
        except OSError as exc:
            log(f"tls failure: {exc}")

        time.sleep(10)


if __name__ == "__main__":
    main()
