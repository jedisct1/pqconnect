import logging
import sys
from multiprocessing import Pipe
from multiprocessing.connection import wait
from os import urandom
from queue import Queue
from socket import AF_INET, SOCK_DGRAM, socket
from sys import getrefcount
from threading import Event, Thread
from typing import Any
from unittest import TestCase, main
from unittest.mock import patch

from pqconnect.common.constants import (
    COOKIE_PREFIX,
    HANDSHAKE_FAIL,
    INITIATION_MSG,
    PQCPORT,
    TUNNEL_MSG,
)
from pqconnect.cookie.cookiemanager import CookieManager
from pqconnect.iface import create_tun_interface, tun_listen
from pqconnect.peer import Peer
from pqconnect.tundevice import TunDevice
from pqconnect.tunnel import TunnelSession
from scapy.all import DNS, IP, TCP, UDP

logging.basicConfig(
    level=9,
    format="%(asctime)s,%(msecs)d %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stderr,
)

EXT_IP = "127.0.0.1"
INT_IP = "172.16.0.2"
MY_IP = "172.16.0.1"
PREFIX_LEN = 24
dev_name = "test_pqc0"


class DumbServer:
    def complete_handshake(self, packet: Any, addr: Any) -> bool:
        return True


result_queue: Queue = Queue()


def send_bytes(cls: Any, bts: bytes) -> None:
    result_queue.put(bts)


def sock_send(cls: Any, bts: bytes, addr: Any) -> None:
    result_queue.put((bts, addr))


class TestTunDevice(TestCase):
    def setUp(self) -> None:
        # create cookie_manager
        self.cookie_manager = CookieManager(urandom(32))

        # create TUN device
        self.tun_file = create_tun_interface(dev_name, MY_IP, PREFIX_LEN)

        # create pipe for tun_listener <-> client tundevice communication
        self.p_conn, self.c_conn = Pipe()

        # Start tun_listener as a thread
        self.event = Event()
        self.tun_thread = Thread(
            target=tun_listen, args=(self.tun_file, self.p_conn, self.event)
        )
        self.tun_thread.start()

        # Create client tun device
        self.dev = TunDevice(
            PQCPORT,
            server=DumbServer(),
            cookie_manager=self.cookie_manager,
            tun_conn=self.c_conn,
            dev_name=dev_name,
        )

    def tearDown(self) -> None:
        self.event.set()
        self.tun_thread.join()

        self.p_conn.close()
        self.c_conn.close()
        self.tun_file.close()
        self.dev.close()

    def test_get_ip_from_iface(self) -> None:
        """Tests that function returns the correct information in the correct
        format

        """
        self.assertEqual(
            self.dev._get_ip_from_iface(dev_name), (MY_IP, PREFIX_LEN)
        )

    def test__pton(self) -> None:
        """Tests that _pton correctly returns the masked address as an integer"""

        self.dev._prefix_len = 16
        self.assertEqual(self.dev._pton("1.2.3.4"), (3 << 8) + 4)

        self.dev._prefix_len = 24
        self.assertEqual(self.dev._pton("1.2.3.4"), 4)

        self.dev._prefix_len = 20
        self.assertEqual(self.dev._pton("1.2.3.4"), (3 << 8) + 4)

        self.dev._prefix_len = 20
        self.assertEqual(self.dev._pton("1.2.131.4"), (3 << 8) + 4)

        self.dev._prefix_len = 16
        self.assertEqual(self.dev._pton("1.2.131.4"), (131 << 8) + 4)

    def test__make_local_ipv4(self) -> None:
        self.dev._prefix_len = 12
        self.assertEqual(self.dev._make_local_ipv4(0), "172.16.0.0")
        self.assertEqual(self.dev._make_local_ipv4(127), "172.16.0.127")
        self.assertEqual(self.dev._make_local_ipv4(256), "172.16.1.0")
        self.assertEqual(self.dev._make_local_ipv4(257), "172.16.1.1")
        self.assertEqual(self.dev._make_local_ipv4(65535), "172.16.255.255")
        self.assertEqual(self.dev._make_local_ipv4(1048575), "172.31.255.255")

        self.dev._prefix_len = 24
        try:
            self.dev._make_local_ipv4(256)
            self.assertTrue(False, "Should have thrown an exception")
        except ValueError:
            self.assertTrue(True)

    def test_get_next_ip(self) -> None:
        """Tests that test_get_next_ip returns an IP with the subnet prefix and
        the suffix equal to dev._next_ip

        """

        self.dev._prefix_len = 12
        self.dev._next_ip = 5
        self.assertEqual(self.dev.get_next_ip(), "172.16.0.5")

        self.dev._next_ip = 1005
        self.assertEqual(self.dev.get_next_ip(), "172.16.3.237")

    def test__is_in_subnet(self) -> None:
        self.assertTrue(self.dev._is_in_subnet("10.10.0.1", 16, "10.10.0.1"))
        self.assertTrue(self.dev._is_in_subnet("10.10.0.1", 16, "10.10.127.1"))
        self.assertTrue(self.dev._is_in_subnet("10.10.0.1", 16, "10.10.128.1"))
        self.assertFalse(
            self.dev._is_in_subnet("10.10.0.1", 17, "10.10.128.1")
        )
        self.assertTrue(self.dev._is_in_subnet("10.10.0.1", 15, "10.11.128.1"))
        self.assertFalse(
            self.dev._is_in_subnet("10.10.0.1", 16, "10.11.128.1")
        )

    def test_add_peer(self) -> None:
        """Tests that add_peer successfully updates the state of the object"""

        # Server peer
        self.dev._server = None
        int_ip = self.dev.get_next_ip()
        peer = Peer("1.2.3.4", int_ip, pkh=b"A" * 32)
        peer.set_tunnel(TunnelSession(b"0" * 32, b"1" * 32, b"2" * 32))
        self.dev.add_peer(peer)
        try:
            self.assertEqual(self.dev.get_peer_by_pkh(b"A" * 32), peer)
            self.assertNotEqual(self.dev.get_next_ip(), int_ip)
        except Exception:
            self.assertTrue(False)

        finally:
            peer.close()

    def test_remove_expired_peers(self) -> None:
        """Tests that peers without an active session are removed"""
        ext_ip1 = "1.2.3.4"
        ext_ip2 = "4.3.2.1"
        int_ip1 = "2.3.4.5"
        int_ip2 = "5.4.3.2"
        peer1 = Peer(ext_ip1, int_ip1, pkh=urandom(32))
        peer2 = Peer(ext_ip2, int_ip2, pkh=urandom(32))
        tun1 = TunnelSession(urandom(32), urandom(32), urandom(32))
        tun2 = TunnelSession(urandom(32), urandom(32), urandom(32))
        tid1 = tun1.get_tid()
        tid2 = tun2.get_tid()
        peer1.set_tunnel(tun1)
        self.assertEqual(peer1.get_tid(), tid1)
        peer2.set_tunnel(tun2)
        self.dev.add_peer(peer1)
        self.dev.add_peer(peer2)
        tun1.close()
        self.dev._end_cond.set()
        self.dev.remove_expired_peers()

        try:
            self.dev._tid2peer[tid1]
            self.assertTrue(False, "peer shouldn't exist")

        except KeyError:
            self.assertTrue(True)

        try:
            self.dev._ext2peer[ext_ip1]
            self.assertTrue(False, "peer shouldn't exist")

        except KeyError:
            self.assertTrue(True)

        try:
            self.dev._int2peer[int_ip1]
            self.assertTrue(False, "peer shouldn't exist")

        except KeyError:
            self.assertTrue(True)

        try:
            self.dev._tid2peer[tid2]
            self.assertTrue(True)

        except KeyError:
            self.assertTrue(False, "peer should exist")

        finally:
            tun2.close()
            peer2.close()
            peer1.close()

    def test_remove_peer(self) -> None:
        """Checks that after remove_peer is called on a peer that the reference
        count is equal to 1 (because we're checking it)

        """
        peer = Peer("1.2.3.4", "2.3.4.5", pkh=b"a" * 32)
        peer.set_tunnel(TunnelSession(b"0" * 32, b"1" * 32, b"2" * 32))
        refct = getrefcount(peer)
        self.dev.add_peer(peer)
        self.assertNotEqual(getrefcount(peer), refct)
        self.dev.remove_peer(peer)
        new_refct = getrefcount(peer)
        self.assertEqual(
            getrefcount(peer),
            refct,
            f"original ref_count: {refct}; new ref_count {new_refct}",
        )

    def test_get_peer_by_pkh(self) -> None:
        """get method"""
        # Delete server since this only makes sense for the client
        self.dev._server = None
        try:
            peer = Peer("1.2.3.4", "2.3.4.5", pkh=b"hello")
            peer.set_tunnel(TunnelSession(b"0" * 32, b"1" * 32, b"2" * 32))
            if not self.dev.add_peer(peer):
                raise Exception("Could not add peer")
            self.assertEqual(self.dev.get_peer_by_pkh(b"hello"), peer)
        except Exception as e:
            self.assertTrue(False, f"unable to find peer: {e}")
        finally:
            self.dev.remove_peer(peer)

        # Should except
        try:
            peer = Peer("1.2.3.4", "2.3.4.5")
            peer.set_tunnel(TunnelSession(b"0" * 32, b"1" * 32, b"2" * 32))
            if not self.dev.add_peer(peer):
                raise Exception("Could not add peer")
            self.assertEqual(self.dev.get_peer_by_pkh(b"hello"), peer)
        except Exception as e:
            self.assertTrue(True, e)
        finally:
            self.dev.remove_peer(peer)

        # should fail
        try:
            peer = Peer("1.2.3.4", "2.3.4.5", pkh=b"asdlfkj")
            peer.set_tunnel(TunnelSession(b"0" * 32, b"1" * 32, b"2" * 32))
            if not self.dev.add_peer(peer):
                raise Exception("Could not add peer")
            self.dev._pkh2peer.pop(b"asdlfkj")
            self.assertEqual(self.dev.get_peer_by_pkh(b"asdlfkj"), peer)
        except Exception as e:
            self.assertTrue(True, e)
        finally:
            self.dev.remove_peer(peer)

    def test__update_incoming_pk_addrs(self) -> None:
        """Makes sure packet is correctly mangled"""
        # Packet is a DNS response for a query to google
        udp_pkt = bytes.fromhex(
            "4500006f69f9400040114a4fc0a80201c0a802e400358f9c005bd82a786a"
            "8180000100010000000106676f6f676c6503636f6d0000010001c00c0001"
            "0001000000200004acd9a32e00002904d000000000001c000a0018dc75c2"
            "403b7b5ddc793ac4f9648680d2e418721a13b45a3a"
        )
        tcp_pkt = bytes.fromhex(
            "450000341fdc4000400606d20a0a00010a0a0002bf1e01bbc705299f131b8"
            "122801001f5cf7900000101080af319cb02e533a82b"
        )

        # UDP
        pkt = IP(udp_pkt)
        payload = bytes(pkt[UDP][DNS])
        self.assertNotEqual(pkt.src, "1.2.3.4")
        self.assertNotEqual(pkt.dst, self.dev._my_ip)
        new_packet = self.dev._update_incoming_pk_addrs(udp_pkt, "1.2.3.4")
        new_pkt = IP(new_packet)
        new_payload = bytes(new_pkt[UDP][DNS])
        self.assertEqual(payload, new_payload)
        self.assertEqual(new_pkt.src, "1.2.3.4")
        self.assertEqual(new_pkt.dst, self.dev._my_ip)

        # TCP
        pkt = IP(tcp_pkt)
        payload = bytes(pkt[TCP].payload)
        self.assertNotEqual(pkt.src, "1.2.3.4")
        self.assertNotEqual(pkt.dst, self.dev._my_ip)
        new_packet = self.dev._update_incoming_pk_addrs(tcp_pkt, "1.2.3.4")
        new_pkt = IP(new_packet)
        new_payload = bytes(new_pkt[TCP].payload)
        self.assertEqual(payload, new_payload)
        self.assertEqual(new_pkt.src, "1.2.3.4")
        self.assertEqual(new_pkt.dst, self.dev._my_ip)

    def test__generate_cookie(self) -> None:
        """Checks that cookie can be generated for a peer"""
        peer = Peer("1.2.3.4", "2.3.4.5")
        tunnel_session = TunnelSession(b"a" * 32, b"b" * 32, b"c" * 32)
        peer.set_tunnel(tunnel_session)
        cookie = self.dev._generate_cookie(peer)
        self.assertNotEqual(cookie, b"")
        peer.close()

    def test_prune_connection(self) -> None:
        """Tests that prune connection removes the least recently used session"""
        tids = [b"0" * 32]
        peer0 = Peer("1.2.3.4", "2.3.4.5")
        ts0 = TunnelSession(tids[0], b"1" * 32, b"2" * 32)
        peer0.set_tunnel(ts0)

        self.assertTrue(self.dev.add_peer(peer0))

        # make sure prune is deterministic
        for _ in range(30):
            tid = urandom(32)
            peer = Peer(self.dev.get_next_ip(), self.dev.get_next_ip())
            ts = TunnelSession(tid, urandom(32), urandom(32))
            peer.set_tunnel(ts)
            tids.append(tid)

            self.assertTrue(self.dev.add_peer(peer))
            peer.encrypt(b"hello")

        # Should remove peer0
        self.dev._prune_connection()

        try:
            peer = self.dev._tid2peer[tids[0]]
            self.assertTrue(False, "peer should not exist")
        except Exception:
            self.assertTrue(True)

        for i in range(1, 31):
            try:
                peer = self.dev._tid2peer[tids[i]]
                self.assertTrue(True)
                self.dev.remove_peer(peer)
            except Exception:
                self.assertTrue(False, "peer should exist")

    def test_queue_incoming(self) -> None:
        """tests that packets are correctly sorted into their respective
        queues

        """
        addr = self.dev._tunnel_sock.getsockname()
        s = socket(AF_INET, SOCK_DGRAM)
        s.bind(("127.0.0.1", 54321))
        my_addr = s.getsockname()
        self.dev._server = 1  # just make server not None

        # handshake queue
        s.sendto(INITIATION_MSG, addr)
        self.dev._queue_incoming()
        self.assertEqual(
            self.dev._handshake_queue.get(), (INITIATION_MSG, my_addr)
        )

        # cookie queue
        s.sendto(COOKIE_PREFIX, addr)
        self.dev._queue_incoming()
        self.assertEqual(
            self.dev._session_resume_queue.get(), (COOKIE_PREFIX, my_addr)
        )

        # tunnel msg
        s.sendto(TUNNEL_MSG, addr)
        self.dev._queue_incoming()
        self.assertEqual(self.dev._recv_queue.get(), (TUNNEL_MSG, my_addr))

        # handshake fail
        peer = Peer(my_addr[0], "10.0.0.5")
        peer.set_tunnel(TunnelSession(b"0" * 32, b"1" * 32, b"2" * 32))
        self.dev.add_peer(peer)
        self.assertEqual(self.dev._ext2peer[my_addr[0]], peer)
        s.sendto(HANDSHAKE_FAIL, addr)
        self.dev._queue_incoming()
        try:
            self.dev.get_peer_by_pkh(b"0" * 32)
            self.assertTrue(False, "peer should have been removed")
        except Exception:
            self.assertTrue(True)

        peer.close()
        s.close()

    @patch("pqconnect.pqcserver.PQCServer", new="__main__.DumbServer")
    def test__process_handshake_from_queue(self) -> None:
        """Tests that queued handshake messages are processed correctly"""
        # handshake queue
        addr = self.dev._tunnel_sock.getsockname()
        s = socket(AF_INET, SOCK_DGRAM)

        # handshake queue
        s.sendto(INITIATION_MSG, addr)
        self.dev._queue_incoming()
        self.assertEqual(
            self.dev._handshake_queue.qsize(), 1, "Queue should not be empty"
        )
        self.dev._process_handshake_from_queue()
        self.assertEqual(
            self.dev._handshake_queue.qsize(), 0, "Queue should be empty"
        )
        s.close()

    def test__process_cookie_from_queue(self) -> None:
        """Tests that queued cookie messages are processed correctly"""
        tid = urandom(32)
        sr = b"B" * 32
        rr = b"C" * 32

        my_tun = TunnelSession(tid, sr, rr)

        peer = Peer("1.2.3.4", self.dev.get_next_ip())
        peer.set_tunnel(my_tun)
        self.assertTrue(self.dev.add_peer(peer))

        # Make sure peer exists
        try:
            peer0 = self.dev._tid2peer[tid]
            self.assertEqual(peer0.get_external_ip(), "1.2.3.4")
        except KeyError:
            self.assertTrue(False, "peer was not added correctly")

        cookie = self.dev._generate_cookie(peer)

        self.dev.remove_peer(peer0)

        # Make sure peer doesn't exist
        try:
            self.dev._tid2peer[tid]
            self.assertTrue(False, "Peer exists but shouldn't")
        except KeyError:
            self.assertTrue(True)

        self.dev._session_resume_queue.put(
            (cookie.bytes(), (peer.get_external_ip(), peer.get_pqcport()))
        )
        self.assertTrue(self.dev._process_cookie_from_queue())

        try:
            peer1 = self.dev._tid2peer[tid]
            self.assertEqual(peer.get_external_ip(), "1.2.3.4")
            peer1.close()
        except KeyError:
            self.assertTrue(False, "peer not found")

        finally:
            peer.close()

    @patch("multiprocessing.connection.Connection.send_bytes", new=send_bytes)
    def test__receive_from_queue(self) -> None:
        """Tests that queued session messages are processed correctly"""
        # Create some tunnel session objects

        ## TID
        tid = urandom(32)

        ## Root keys
        sr = urandom(32)
        their_rr = bytes([a for a in sr])
        rr = urandom(32)
        their_sr = bytes([a for a in rr])

        ## TunnelSession
        their_tun = TunnelSession(tid, their_sr, their_rr)
        tun = TunnelSession(tid, sr, rr)

        # Create peer
        peer = Peer("1.2.3.4", self.dev.get_next_ip())
        peer.set_tunnel(tun)
        self.dev.add_peer(peer)

        # Create plaintext packet
        msg = IP(src=peer.get_internal_ip()) / UDP(sport=12345) / b"hello"
        msgbts = bytes(msg)

        # Enqueue encrypted packet
        self.assertEqual(self.dev._recv_queue.qsize(), 0)

        self.dev._recv_queue.put(
            (
                their_tun.tunnel_send(msgbts),
                (peer.get_external_ip(), 12345),
            )
        )
        # Make sure result_queue is empty
        while True:
            try:
                _ = result_queue.get_nowait()
            except Exception:
                break

        self.dev._receive_from_queue()

        t = result_queue.get()
        self.assertEqual(bytes(IP(t)[UDP].payload), b"hello")
        self.dev.remove_peer(peer)
        their_tun.close()
        tun.close()
        peer.close()

    def test__queue_send_packet(self) -> None:
        """Tests that outgoing session messages are queued correctly"""
        peer = Peer("1.2.3.4", self.dev.get_next_ip())
        print(f"internal IP: {peer.get_internal_ip()}")
        tun = TunnelSession(b"a" * 32, b"b" * 32, b"c" * 32)
        peer.set_tunnel(tun)
        self.dev.add_peer(peer)

        sock = socket(AF_INET, SOCK_DGRAM)
        sock.sendto(b"hello", (peer.get_internal_ip(), peer.get_pqcport()))
        self.dev._queue_send_packet()
        print(f"queue size: {self.dev._send_queue.qsize()}")
        t = IP(self.dev._send_queue.get())
        while not t.proto == 17:
            conn = wait([self.dev._tun_conn], 1)
            if not conn:
                self.assertTrue(False, "did not queue packet")
            self.dev._queue_send_packet()
            t = IP(self.dev._send_queue.get())

        self.assertEqual(bytes(t[UDP].payload), b"hello")
        sock.close()

    @patch("socket.socket.sendto", new=sock_send)
    def test__send_from_queue(self) -> None:
        """Tests that queued outgoing session messages are sent correctly"""
        tid = urandom(32)
        sr = urandom(32)
        their_rr = bytes([a for a in sr])  # create new object
        rr = urandom(32)
        their_sr = bytes([a for a in rr])
        their_tun = TunnelSession(tid, their_sr, their_rr)
        tun = TunnelSession(tid, sr, rr)

        peer = Peer("1.2.3.4", self.dev.get_next_ip())
        peer.set_tunnel(tun)
        self.dev.add_peer(peer)

        pkt = IP(dst=peer.get_internal_ip()) / UDP(dport=1234) / b"hello"
        self.dev._send_queue.put(bytes(pkt))

        # make sure result_queue is empty
        while True:
            try:
                _ = result_queue.get_nowait()
            except Exception:
                break

        # send
        self.dev._send_from_queue()

        t, addr = result_queue.get()
        pkt = their_tun.tunnel_recv(t)
        their_tun.close()
        peer.close()
        self.assertEqual(bytes(IP(pkt)[UDP].payload), b"hello")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
