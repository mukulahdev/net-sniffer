import unittest
from unittest import mock

import arp_guard as ag
from scapy.all import ARP, Ether

GATEWAY = "192.168.230.2"
REAL = "00:50:56:fb:b2:76"
FAKE = "de:ad:be:ef:00:01"


class TestGuard(unittest.TestCase):
    def test_first_answer_is_learned(self):
        guard = ag.Guard()
        self.assertEqual(guard.check(GATEWAY, REAL), "new")
        self.assertEqual(guard.known[GATEWAY], REAL)

    def test_same_answer_is_fine(self):
        guard = ag.Guard()
        guard.check(GATEWAY, REAL)
        self.assertEqual(guard.check(GATEWAY, REAL.upper()), "same")
        self.assertEqual(guard.alarms, [])

    def test_new_name_tag_raises_an_alarm(self):
        guard = ag.Guard()
        guard.check(GATEWAY, REAL)
        self.assertEqual(guard.check(GATEWAY, FAKE), "changed")
        self.assertEqual(len(guard.alarms), 1)
        self.assertEqual(guard.known[GATEWAY], REAL)  # still trusts the first


class TestHandle(unittest.TestCase):
    def setUp(self):
        ag.guard = ag.Guard()

    def answer(self, mac):
        return Ether() / ARP(op=ag.IS_AT, psrc=GATEWAY, hwsrc=mac)

    def test_questions_are_ignored(self):
        with mock.patch("builtins.print"):
            ag.handle(Ether() / ARP(op=1, psrc=GATEWAY, pdst="192.168.230.1"))
        self.assertEqual(ag.guard.known, {})

    def test_spoofed_answer_prints_an_alarm(self):
        with mock.patch("builtins.print") as out:
            ag.handle(self.answer(REAL))
            ag.handle(self.answer(FAKE))
        printed = " ".join(str(c.args[0]) for c in out.call_args_list)
        self.assertIn("!! ALARM", printed)


if __name__ == "__main__":
    unittest.main()
