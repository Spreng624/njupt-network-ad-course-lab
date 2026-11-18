#!/usr/bin/env python3
import html
import http.server
import os
import ssl
import threading
import urllib.parse
import uuid


FLAG_INJECT = open("/run/lab/inject.flag", encoding="utf-8").read().strip()
FLAG_SCAN = open("/run/lab/scan.flag", encoding="utf-8").read().strip()
HASHES = open("/run/lab/hashes.txt", encoding="utf-8").read()
SESSIONS = set()
USERS = {"alice": "victim123", "admin": "admin123"}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "LabPortal/1.0"
    sys_version = "Python"

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)

    def send_text(self, status, body, headers=None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Lab-Vulnerable", "session-injection-demo")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def session(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            key, _, value = part.strip().partition("=")
            if key == "session" and value in SESSIONS:
                return value
        return None

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/health":
            self.send_text(200, "ok\n")
            return
        if parsed.path == "/login":
            user = query.get("user", [""])[0]
            password = query.get("pass", [""])[0]
            if USERS.get(user) != password:
                self.send_text(401, "invalid credentials\n")
                return
            token = uuid.uuid4().hex
            SESSIONS.add(token)
            self.send_text(
                200,
                "login ok\nrole=user\n",
                {"Set-Cookie": f"session={token}; Path=/; SameSite=Lax"},
            )
            return
        if parsed.path == "/api/transfer":
            if not self.session():
                self.send_text(401, "missing or invalid session\n")
                return
            amount = int(query.get("amount", ["1"])[0])
            account = html.escape(query.get("account", ["acct-1"])[0])
            if amount <= 10:
                self.send_text(200, f"transfer accepted: {account} amount={amount}\n")
            else:
                self.send_text(200, f"injected transfer accepted: {account} amount={amount}\nFLAG_INJECT={FLAG_INJECT}\n")
            return
        if parsed.path == "/loot/hashes.txt":
            self.send_text(200, HASHES)
            return
        if parsed.path == "/vuln":
            self.send_text(200, f"legacy endpoint exposed\nFLAG_SCAN={FLAG_SCAN}\n")
            return
        if parsed.path == "/":
            self.send_text(200, "Intranet portal\n/login?user=alice&pass=victim123\n")
            return
        self.send_text(404, "not found\n")


class ReuseServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True


def serve_http():
    server = ReuseServer(("0.0.0.0", 80), Handler)
    server.serve_forever()


def serve_https():
    server = ReuseServer(("0.0.0.0", 443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/run/lab/target.crt", "/run/lab/target.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    threading.Thread(target=serve_https, daemon=True).start()
    serve_http()
