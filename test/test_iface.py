from ipaddress import IPv4Network
from multiprocessing import Pipe
from select import select
from signal import SIGALRM, alarm, signal
from socket import AF_INET, SOCK_DGRAM, socket
from threading import Event
from time import sleep
from unittest import TestCase

from pqconnect.iface import (
    check_overlapping_address,
    create_tun_interface,
    tun_listen,
)
from scapy.all import IP, UDP


class TestiFace(TestCase):
    def setUp(self) -> None:
        self.tunfile = create_tun_interface("iface_test", "10.55.42.254", 31)

    def tearDown(self) -> None:
        self.tunfile.close()

    def test_check_overlapping_addresses(self) -> None:
        vectors = [
            {
                "address": "192.168.3.25",
                "prefix_len": 16,
                "addrs": [("192.168.1.1", 16)],
                "result": False,
            },
            {
                "address": "192.168.3.25",
                "prefix_len": 32,
                "addrs": [("192.168.3.25", 32)],
                "result": False,
            },
            {
                "address": "10.0.0.0",
                "prefix_len": 8,
                "addrs": [("10.255.255.255", 8)],
                "result": False,
            },
            {
                "address": "192.168.3.25",
                "prefix_len": 16,
                "addrs": [("10.10.0.1", 16)],
                "result": True,
            },
            {
                "address": "192.168.3.25",
                "prefix_len": 24,
                "addrs": [("192.168.1.1", 24)],
                "result": True,
            },
            {
                "address": "10.10.0.1",
                "prefix_len": 24,
                "addrs": [
                    ("192.168.1.1", 20),
                    ("10.10.10.1", 24),
                    ("172.16.0.5", 12),
                ],
                "result": True,
            },
            {
                "address": "10.10.0.1",
                "prefix_len": 16,
                "addrs": [
                    ("192.168.1.1", 20),
                    ("10.10.10.1", 24),  # overlap
                    ("172.16.0.5", 12),
                ],
                "result": False,
            },
            {
                "address": "10.10.128.1",
                "prefix_len": 23,
                "addrs": [
                    ("192.168.1.1", 20),
                    ("10.10.129.1", 23),  # overlap
                    ("172.16.0.5", 12),
                ],
                "result": False,
            },
        ]

        for v in vectors:
            addrs = [IPv4Network(nw, strict=False) for nw in v["addrs"]]
            self.assertEqual(
                check_overlapping_address(
                    v["address"], v["prefix_len"], iface_addrs=addrs
                ),
                v["result"],
            )

    def test_tun_listen(self) -> None:
        """Tests that tun_listen forwards packets in both directions. This test
        is synchronous, but alarm() is used to send a SIGALRM to kill the while
        loop in tun_listen

        """

        try:
            # some test-specific setup:
            ## local is used by this test. remote is used by the tun_listen function
            local, remote = Pipe()

            ## signaling object and signal handler

            evt = Event()

            def handler(signum: int, frame: object) -> None:
                evt.set()

            signal(SIGALRM, handler)

            # Direction localhost > network

            ## python process sends a packet that routes to TUN dev
            s = socket(AF_INET, SOCK_DGRAM)
            s.sendto(b"hello", ("10.55.42.255", 12345))

            ## the packet should have arrived at the TUN device.
            ## Run tun_listen() to read the packet from the TUN device
            ## and forward it to our 'local' pipe
            alarm(1)
            tun_listen(self.tunfile, remote, evt)

            ## read from the pipe
            while True:
                readable = select([local], [], [], 0.1)
                # fail if empty
                if not readable:
                    print(readable)
                    self.assertFalse(True)

                data = local.recv_bytes()
                p = IP(data)

                # If the OS wrote something else to the TUN device, skip and repeat
                if UDP not in p:
                    continue

                self.assertEqual(bytes(p[UDP].payload), b"hello")
                break

            # Direction network > localhost

            ## reset event object
            evt.clear()

            ## Construct full echo packet with headers
            src = p.src
            dst = p.dst
            sport = p.sport
            dport = p.dport

            return_pkt = (
                IP(src=dst, dst=src) / UDP(sport=dport, dport=sport) / b"howdy"
            )

            ## send packet to be written to TUN device
            ## and thus forwarded back to the application socket
            local.send_bytes(bytes(return_pkt))

            alarm(1)
            tun_listen(self.tunfile, remote, evt)

            data, _ = s.recvfrom(100)
            self.assertEqual(data, b"howdy")

        finally:
            # cleanup
            s.close()
            local.close()
            remote.close()
