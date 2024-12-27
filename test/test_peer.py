from unittest import TestCase

from pqconnect.common.crypto import dh, randombytes, skem
from pqconnect.peer import Peer, PeerState
from pqconnect.tunnel import TunnelSession


class TestPeer(TestCase):
    def setUp(self) -> None:
        self.tid = randombytes(32)
        self.t1_send_root = randombytes(32)
        self.t1_recv_root = randombytes(32)
        self.t2_send_root = bytes(
            [self.t1_recv_root[i] for i in range(len(self.t1_recv_root))]
        )
        self.t2_recv_root = bytes(
            [self.t1_send_root[i] for i in range(len(self.t1_send_root))]
        )
        self.my_tun = TunnelSession(
            self.tid, self.t1_send_root, self.t1_recv_root
        )
        self.their_tun = TunnelSession(
            self.tid, self.t2_send_root, self.t2_recv_root
        )
        self.ip_addr = "1.2.3.4"
        self.ip_addr2 = "2.3.4.5"
        self.peer = Peer(self.ip_addr, self.ip_addr2)
        self.peer.set_tunnel(self.my_tun)

    def tearDown(self) -> None:
        self.my_tun.close()
        self.their_tun.close()

    def test_init(self) -> None:
        try:
            peer = Peer("1", self.ip_addr)
            self.assertTrue(False, "exception not raised")

        except ValueError:
            self.assertTrue(True)

        try:
            peer = Peer(self.ip_addr, "1")
            self.assertTrue(False, "exception not raised")

        except ValueError:
            self.assertTrue(True)

        mceliece = randombytes(skem.PUBLICKEYBYTES)
        x25519 = randombytes(dh.lib25519_dh_PUBLICKEYBYTES)

        # Correct example
        try:
            peer = Peer(
                self.ip_addr,
                self.ip_addr2,
                pkh=b"5" * 52,
                mceliece_pk=mceliece,
                x25519_pk=x25519,
                port=12345,
            )
            self.assertTrue(True)
        except Exception as e:
            self.assertTrue(False, e)

    def test_state_machine(self) -> None:
        """Tests that the peer state reflects the state machine"""
        peer = Peer(self.ip_addr, self.ip_addr)
        self.assertEqual(peer.get_state(), PeerState.NEW)

        peer.set_tunnel(self.my_tun)
        self.assertEqual(peer.get_state(), PeerState.ESTABLISHED)

        ct = self.their_tun.tunnel_send(b"hello")
        peer.decrypt(ct)
        self.assertEqual(peer.get_state(), PeerState.ALIVE)

        ct = self.their_tun.tunnel_send(b"hello")
        self.my_tun.close()  # mimic a timeout
        self.assertFalse(self.my_tun.is_alive())
        peer.decrypt(ct)
        self.assertEqual(peer.get_state(), PeerState.EXPIRED)

        peer.error()
        self.assertEqual(peer.get_state(), PeerState.ERROR)

        peer.close()
        self.assertEqual(peer.get_state(), PeerState.CLOSED)

    def test_get_pkh(self) -> None:
        """Tests that get_pkh returns the pkh from the constructor"""
        pkh = randombytes(32)
        peer = Peer(self.ip_addr, self.ip_addr2)
        self.assertEqual(peer.get_pkh(), b"")

        peer = Peer(self.ip_addr2, self.ip_addr, pkh=pkh)
        self.assertEqual(peer.get_pkh(), pkh)

    def test_encrypt_decrypt(self) -> None:
        peer = Peer(self.ip_addr, self.ip_addr)
        peer.set_tunnel(self.my_tun)
        peer_symmetric = Peer("1.2.3.4", "10.10.0.6")  # ip addr doesn't matter
        peer_symmetric.set_tunnel(self.their_tun)
        hello0 = b"hello0"
        hello1 = b"hello1"

        ct = peer.encrypt(hello0)
        self.assertNotEqual(ct, b"")
        self.assertEqual(peer_symmetric.decrypt(ct), hello0)

        ct = peer_symmetric.encrypt(hello1)
        self.assertEqual(peer.decrypt(ct), hello1)
