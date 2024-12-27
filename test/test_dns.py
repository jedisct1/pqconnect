from multiprocessing import Event, Pipe, Process, synchronize
from multiprocessing.connection import Connection
from socket import getaddrinfo
from unittest import TestCase

from pqconnect.common.constants import A_RECORD
from pqconnect.dnsproxy import DNSProxy
from pqconnect.nft import NfqueueBuilder
from scapy.all import DNSRR, IP, UDP

INT_IP = "1.2.3.4"


def dns_do(conn: Connection, cv: synchronize.Event) -> None:
    """Simple function that mimics the DNS mangling by the client"""
    while not cv.is_set():
        data = conn.recv_bytes()
        p = IP(data)
        # replace all DNS answer records with internal ip
        for i in range(p.ancount):
            if DNSRR in p.an[i]:
                if p.an[i][DNSRR].type == A_RECORD:
                    p.an[i][DNSRR].rdata = INT_IP

        # recompute checksums
        del p[IP].len
        del p[IP].chksum
        del p[UDP].len
        del p[UDP].chksum
        conn.send_bytes(bytes(p))


class DNSProxyTest(TestCase):
    def setUp(self) -> None:
        self.local_conn, self.proxy_conn = Pipe()
        self.end_cond = Event()
        self.proxy = DNSProxy(self.proxy_conn, "pqconnect_filter_test")
        self.proxy_proc = Process(target=self.proxy.run)
        self.dns_proc = Process(
            target=dns_do, args=(self.local_conn, self.end_cond)
        )
        self.builder = NfqueueBuilder("test_table")

    def tearDown(self) -> None:
        self.proxy.close()

    def test_nftables_integration(self) -> None:
        """Tests that packets queued by the netfilterqueue rule from the
        NfqueueBuilder object are handled as espected.

        """
        try:
            self.builder.build()
            self.proxy_proc.start()
            self.dns_proc.start()

            info = getaddrinfo("www.jlev.in", 12345)

            addr = info[0][4][0]

            self.assertEqual(addr, INT_IP)

        finally:
            self.proxy_proc.kill()
            self.end_cond.set()
            self.dns_proc.kill()
            self.builder.tear_down()
