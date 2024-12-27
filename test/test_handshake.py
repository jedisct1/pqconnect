from unittest import TestCase

from pqconnect.common.crypto import dh, ekem, skem
from pqconnect.keys import PKTree
from pqconnect.peer import Peer
from pqconnect.pqcclient import PQCClientConnectionHandler
from pqconnect.pqcserver import PQCServerHS


class DummyServer:
    def is_tid_seen(self, tid: bytes) -> bool:
        """Return False so that the PQCServerHS completes the handshake"""
        return False


class DummyClient:
    pass


class DummyDevice:
    pass


class HandshakeTest(TestCase):
    def setUp(self) -> None:
        self.skem = skem
        self.pqpk, self.pqsk = self.skem.keypair()
        self.npqpk, self.npqsk = dh.dh_keypair()
        self.client = DummyClient()
        self.device = DummyDevice()
        self.server = DummyServer()
        self.pktree = PKTree(self.pqpk, self.npqpk)

    def test_handshake_0rtt(self) -> None:
        e_sntrup_r, e_sntrupsk_r = ekem.keypair()
        e_x25519_r, e_x25519sk_r = dh.dh_keypair()

        mceliece_ct = skem.enc(self.pqpk)
        i = PQCClientConnectionHandler(
            Peer("1.2.3.4", "2.4.6.8", pkh=self.pktree.get_pubkey_hash()),
            self.device,
            self.client,
            mceliece_ct,
        )
        i._s_x25519_r = self.npqpk
        i._e_x25519_r = e_x25519_r
        i._e_sntrup_r = e_sntrup_r
        r = PQCServerHS(
            self.server,
            self.pqsk,
            self.npqsk,
            e_sntrupsk_r,
            e_x25519sk_r,
            None,
            None,
        )
        c0, c1, tag1, c3, tag3, tun_i = i.initiate_handshake_0rtt()
        tun_r = r.complete_handshake_0rtt(c0, c1, tag1, c3, tag3)

        self.assertEqual(
            tun_r.tunnel_recv(tun_i.tunnel_send(b"hello")), b"hello"
        )

        tun_r.close()
        tun_i.close()
