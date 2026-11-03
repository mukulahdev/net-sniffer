#!/usr/bin/env python3
"""arp-guard: raise an alarm when an address suddenly changes its name tag.

Built line by line in the MUKULAH Dev course "Sniff the network".
It only listens: it never sends a packet. Like arpwatch, it remembers which
MAC answers for each IP, and warns when the answer changes (ARP spoofing).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from scapy.all import ARP, sniff

# ARP opcode 2 means an answer: "this address is at this name tag".
IS_AT = 2


@dataclass
class Guard:
    """Remembers which name tag (MAC) each address uses."""

    known: dict[str, str] = field(default_factory=dict)
    alarms: list[str] = field(default_factory=list)

    def check(self, ip: str, mac: str) -> str:
        """Return "new", "same" or "changed" for one answer."""
        mac = mac.lower()
        first = self.known.get(ip)
        if first is None:
            self.known[ip] = mac  # learn it the first time we hear it
            return "new"
        if first == mac:
            return "same"
        self.alarms.append(f"{ip} changed from {first} to {mac}")
        return "changed"  # keep trusting the first name tag


guard = Guard()


def handle(packet) -> None:
    """Called for every ARP packet; only the answers matter."""
    if not packet.haslayer(ARP) or packet[ARP].op != IS_AT:
        return
    ip, mac = packet[ARP].psrc, packet[ARP].hwsrc
    time = datetime.now().strftime("%H:%M:%S")
    result = guard.check(ip, mac)
    if result == "new":
        print(f"{time}  learned  {ip:<16} is at {mac}")
    elif result == "changed":
        print(f"{time}  !! ALARM {ip} was {guard.known[ip]}, now {mac}")
        print("     someone may be pretending to be this address")


def report() -> None:
    """The table we built, and every alarm we raised."""
    print()
    print(f"Known addresses: {len(guard.known)}, alarms: {len(guard.alarms)}")
    for ip, mac in sorted(guard.known.items()):
        print(f"  {ip:<16} {mac}")


def main() -> None:
    # Listen to ARP only, for two minutes, without keeping packets.
    sniff(filter="arp", prn=handle, timeout=120, store=False)
    report()


if __name__ == "__main__":
    main()
