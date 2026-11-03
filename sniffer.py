#!/usr/bin/env python3
"""sniffer: watch your own network traffic, the way Wireshark does.

Built line by line in the MUKULAH Dev course "Sniff the network".
For learning, and only on networks you own. Passwords are never shown:
the tool reports THAT a login travelled in plain text, not what it was.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from urllib.parse import parse_qs

from scapy.all import ARP, IP, TCP, UDP, Raw, sniff

# Form fields that carry a secret. We only ever print their names.
SECRET_FIELDS = {"password", "pass", "pwd", "passwd", "pin"}

# Who talks to whom: (address, address) -> number of packets.
talks: Counter[tuple[str, str]] = Counter()


# ---------------------------------------------------------------- reading


def describe(packet) -> str:
    """One line per packet, like a row in Wireshark's packet list."""
    if packet.haslayer(ARP):
        arp = packet[ARP]
        if arp.op == 1:
            return f"ARP   who has {arp.pdst}? tell {arp.psrc}"
        return f"ARP   {arp.psrc} is at {arp.hwsrc}"
    if packet.haslayer(IP):
        ip = packet[IP]
        for name, layer in (("TCP", TCP), ("UDP", UDP)):
            if packet.haslayer(layer):
                src, dst = packet[layer].sport, packet[layer].dport
                return f"{name}   {ip.src}:{src} -> {ip.dst}:{dst}"
        return f"IP    {ip.src} -> {ip.dst}"
    return packet.summary()


def remember(packet) -> None:
    """Count one packet for its pair of addresses (either direction)."""
    if packet.haslayer(IP):
        pair = tuple(sorted((packet[IP].src, packet[IP].dst)))
        talks[pair] += 1


# ---------------------------------------------------------------- plain text


def plaintext_login(packet) -> dict | None:
    """A login form sent over plain HTTP? Return where, never the secret."""
    if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
        return None
    data = bytes(packet[Raw].load)
    if not data.startswith(b"POST "):
        return None
    head, _, body = data.partition(b"\r\n\r\n")
    path = head.split(b" ")[1].decode(errors="replace")
    form = parse_qs(body.decode(errors="replace"))
    secrets = sorted(name for name in form if name.lower() in SECRET_FIELDS)
    if not secrets:
        return None
    return {"server": packet[IP].dst, "path": path, "fields": secrets}


def handle(packet) -> None:
    """Called by Scapy for every packet it catches."""
    remember(packet)
    time = datetime.now().strftime("%H:%M:%S")
    print(f"{time}  {describe(packet)}")
    login = plaintext_login(packet)
    if login:
        fields = ", ".join(login["fields"])
        print(f"  !! plain-text login to {login['server']}{login['path']}")
        print(f"     secret fields seen: {fields} (values hidden)")


# ---------------------------------------------------------------- report


def report(top: int = 5) -> None:
    """Who talked the most, like Wireshark's Conversations window."""
    print()
    print("Top conversations:")
    for (a, b), count in talks.most_common(top):
        print(f"  {a:<16} <-> {b:<16} {count} packets")


def main() -> None:
    # Only ARP and web traffic, for 60 seconds, without keeping packets.
    sniff(filter="arp or tcp port 80", prn=handle, timeout=60, store=False)
    report()


if __name__ == "__main__":
    main()
