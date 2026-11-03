import unittest

import sniffer as sn
from scapy.all import ARP, IP, TCP, Ether, Raw

LOGIN = (
    b"POST /dvwa/login.php HTTP/1.1\r\nHost: 192.168.230.133\r\n\r\n"
    b"username=admin&password=password&Login=Login"
)


def web(payload: bytes):
    ip = IP(src="192.168.230.128", dst="192.168.230.133")
    return Ether() / ip / TCP(sport=40000, dport=80) / Raw(payload)


class TestDescribe(unittest.TestCase):
    def test_arp_question(self):
        arp = ARP(op=1, psrc="192.168.230.1", pdst="192.168.230.2")
        packet = Ether() / arp
        self.assertIn("who has 192.168.230.2?", sn.describe(packet))

    def test_tcp(self):
        line = sn.describe(web(b"GET / HTTP/1.1\r\n\r\n"))
        self.assertIn("192.168.230.128:40000 -> 192.168.230.133:80", line)


class TestPlainTextLogin(unittest.TestCase):
    def test_login_is_found(self):
        login = sn.plaintext_login(web(LOGIN))
        self.assertEqual(login["path"], "/dvwa/login.php")
        self.assertEqual(login["fields"], ["password"])

    def test_the_secret_is_never_returned(self):
        login = sn.plaintext_login(web(LOGIN))
        self.assertNotIn("password=password", str(login))
        self.assertNotIn("admin", str(login))

    def test_normal_page_is_not_a_login(self):
        page = web(b"GET /dvwa/ HTTP/1.1\r\n\r\n")
        self.assertIsNone(sn.plaintext_login(page))


class TestTalks(unittest.TestCase):
    def test_both_directions_count_together(self):
        sn.talks.clear()
        a = IP(src="192.168.230.128", dst="192.168.230.133")
        b = IP(src="192.168.230.133", dst="192.168.230.128")
        sn.remember(Ether() / a)
        sn.remember(Ether() / b)
        self.assertEqual(sn.talks[("192.168.230.128", "192.168.230.133")], 2)


if __name__ == "__main__":
    unittest.main()
