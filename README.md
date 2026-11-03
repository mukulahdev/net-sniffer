# net-sniffer

**Two small tools to watch your own network and catch an attacker in the middle.**

Built line by line in the [MUKULAH Dev](https://www.youtube.com/@mukulahdev) course
*Sniff the network*. Every line is explained in the videos.

* **`sniffer.py`:** prints one line per packet (ARP and web traffic), warns when a
  login form travels in plain HTTP, and counts who talks to whom. It names the
  secret field but **never prints the secret**.
* **`arp_guard.py`:** like arpwatch, it remembers which MAC answers for each IP,
  and raises an alarm when that answer suddenly changes (ARP spoofing). It only
  listens: it never sends a packet.
* **11 unit tests**, none of which touches the network.

## Requirements

* Linux, Python 3.11 or newer, Scapy (`pip install -r requirements.txt` in a venv)
* Root (or `sudo`) to capture packets

## Use

```bash
git clone https://github.com/mukulahdev/net-sniffer.git
cd net-sniffer
sudo python3 sniffer.py      # 60 seconds of ARP and web traffic
sudo python3 arp_guard.py    # 2 minutes of ARP, alarms on changed MACs
python3 -m unittest -v
```

## Responsible use

For learning, and only on networks you own or have written permission to test.
Reading other people's traffic without permission is illegal in most countries.

## License

MIT. See [LICENSE](LICENSE).
