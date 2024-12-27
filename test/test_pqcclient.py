from multiprocessing import Event, Pipe
from time import time
from unittest import TestCase, main

from pqconnect.common.constants import KEYPORT, NUM_PREKEYS
from pqconnect.common.crypto import dh, skem
from pqconnect.common.util import base32_decode
from pqconnect.iface import create_tun_interface
from pqconnect.keys import PKTree
from pqconnect.log import logger
from pqconnect.peer import Peer
from pqconnect.pqcclient import PQCClient, PQCClientConnectionHandler
from scapy.all import IP

reg_pkt = bytes.fromhex(
    "4500019a035900004011c1be08080808ac13f8180035ae5e018674aaa514818000010003000400050c646574656374706f7274616c0766697265666f7803636f6d0000010001c00c00050001000000b9001e0c646574656374706f7274616c0470726f64066d6f7a617773036e657400c03600050001000001cb00290470726f640c646574656374706f7274616c0470726f6408636c6f75646f7073066d6f7a676370c04fc06000010001000002690004226bdd52c08000020001000086c5001c0b6e732d636c6f75642d63310d676f6f676c65646f6d61696e73c021c08000020001000086c5000e0b6e732d636c6f75642d6334c0b1c08000020001000086c5000e0b6e732d636c6f75642d6332c0b1c08000020001000086c5000e0b6e732d636c6f75642d6333c0b1c0cd00010001000004ec0004d8ef266cc0e7001c00010000012c00102001486048020034000000000000006cc101001c00010001d05900102001486048020036000000000000006cc0cd001c00010000349b00102001486048020038000000000000006c0000291000000000000000"
)
pkh_pkt = bytes.fromhex(
    "".join(
        [
            "450000ad1b9f4000401198dcc0a80201c0a80273",  # IP header
            "0035e8460099c287",  # UDP header
            "ff3e8180000100020000000103777777097071636f6e6e656374036e65740000010001c00c00050001000000010047377071317531687931756a73756b3235386b7278336b7536776439727039366b66786d36346d6763743373336a3236756470353764627531097071636f6e6e656374036e657400c02f000100010000001f0004839b457e0000291000000000000000",
        ]
    )
)

keyserver_txt_pkt = bytes.fromhex(
    "450000a1b69d40004011fd78c0a80201c0a802e40035dcd1008db541df5381800001000100000001026b7337707131713475716835746335397876646a7564366d78353138753066636b73666e6477736d67636e62786a38776d7970666e6d6a667830046a6c657602696e0000100001c00c0010000100000258001a1969703d3139352e3230312e33352e3132313b703d34323432350000290200000000000000"
)


class DummyClient:
    def generate_prekeys(self) -> None:
        pass


class DummyDevice:
    pass


class PQCClientTest(TestCase):
    def setUp(self) -> None:
        self.dev_name = "pqc_test"
        self.TUN = create_tun_interface(self.dev_name, "10.59.0.0", 16)
        self.cli_dns_conn, self.remote_dns_conn = Pipe()
        self.cli_tun_conn, self.remote_tun_conn = Pipe()
        self.end_cond = Event()
        self.cli = PQCClient(
            12345,
            self.cli_tun_conn,
            self.cli_dns_conn,
            self.end_cond,
            dev_name=self.dev_name,
        )

        self.x25519_pk, self.x25519_sk = dh.dh_keypair()
        self.mceliece_pk, self.mceliece_sk = skem.keypair()
        self.pk_tree = PKTree(self.mceliece_pk, self.x25519_pk)
        self.pkh = self.pk_tree.get_pubkey_hash()

    def tearDown(self) -> None:
        self.cli.stop()
        self.TUN.close()

    def test_generate_prekeys(self) -> None:
        """Test that the function creates a cache of valid mceliece ciphertexts
        iff none already exist

        """

        # prekeys should be empty at initialization
        self.assertEqual(self.cli._prekeys, {})

        # Generate prekeys and ensure it returns True, indicating it generated
        # keys
        now = int(time())
        res = self.cli.generate_prekeys(
            self.pkh, self.mceliece_pk, self.x25519_pk, timestamp=now
        )
        self.assertTrue(res)

        # make sure it created NUM_PREKEYS keys
        self.assertEqual(
            len(self.cli._prekeys[self.pkh]["mceliece"]), NUM_PREKEYS
        )

        # make sure timestamp was assigned correctly
        self.assertEqual(self.cli._prekeys[self.pkh]["ts"], now)

        # make sure x25519 public key was stored correctly
        self.assertEqual(self.cli._prekeys[self.pkh]["x25519"], self.x25519_pk)

        # make sure more prekeys are not generated when they already exist
        self.assertFalse(
            self.cli.generate_prekeys(
                self.pkh, self.mceliece_pk, self.x25519_pk
            )
        )

        # make sure the prekeys (mceliece ciphertexts) are decapsulating as
        # expected
        for _ in range(NUM_PREKEYS):
            ct, k = self.cli._prekeys[self.pkh]["mceliece"].pop()
            self.assertEqual(skem.dec(ct, self.mceliece_sk), k)

        # make sure that new prekeys are made correctly after using up all the
        # existing ones
        now = int(time())
        res = self.cli.generate_prekeys(
            self.pkh, self.mceliece_pk, self.x25519_pk, timestamp=now
        )
        self.assertTrue(res)

        # make sure timestamp is updated correctly
        self.assertEqual(self.cli._prekeys[self.pkh]["ts"], now)

    def test_get_pk_hash(self) -> None:
        """Tests that _get_pk_hash correctly parses a public key hash from a
        DNS response packet

        """
        self.assertEqual(
            self.cli._get_pk_hash(IP(pkh_pkt)),
            (
                base32_decode(
                    "u1hy1ujsuk258krx3ku6wd9rp96kfxm64mgct3s3j26udp57dbu1"
                ),
            ),
        )

        self.assertEqual(self.cli._get_pk_hash(IP(reg_pkt)), ())

        self.assertEqual(
            self.cli._get_pk_hash(IP(b"asd;fklajsd;fklajsd;fljasdf")), ()
        )

    def test_get_addrs(self) -> None:
        """Tests that all IPv4 addresses are returned from a DNS response
        packet

        """

        self.assertEqual(self.cli._get_addrs(IP(pkh_pkt)), ["131.155.69.126"])
        self.assertEqual(self.cli._get_addrs(IP(reg_pkt)), ["34.107.221.82"])

    def test__get_cname(self) -> None:
        """Tests that the cname from a DNS response is correctly parsed"""

        self.assertEqual(
            PQCClient._get_domain_name(IP(pkh_pkt)),
            "pq1u1hy1ujsuk258krx3ku6wd9rp96kfxm64mgct3s3j26udp57dbu1.pqconnect.net.",
        )

    def test_dns_handle(self) -> None:
        packet = bytes.fromhex(
            "450000b6025a40004011b1a7c0a80201c0a802e40035de"
            "c000a290a29dea8180000100020000000103777777046a"
            "6c657602696e0000010001c00c000500010000012c003a"
            "37707131396867743133747075356a7076676c746e776e"
            "753033787574756c71666738726c686870763163353833"
            "346e3734626d32327831c010c029000100010000012c00"
            "04c3c9237900002904d000000000001c000a00180a7c80"
            "2684a0b0135b96a3f5648841c70350d61665f76a36"
        )
        pkt, peer = self.cli._dns_handle(pkh_pkt)
        self.assertNotEqual(peer, None)
        self.assertEqual(peer.get_internal_ip(), "10.59.0.2")


class PQCClientConnectionHandlerTest(TestCase):
    def setUp(self) -> None:
        mceliece_pk, mceliece_sk = skem.keypair()
        x25519_pk, x25519_sk = dh.dh_keypair()
        self.pktree = PKTree(mceliece_pk, x25519_pk)
        assert self.pktree.is_complete()
        pkh = base32_decode(
            "u1hy1ujsuk258krx3ku6wd9rp96kfxm64mgct3s3j26udp57dbu1"
        )
        cname = "pq1u1hy1ujsuk258krx3ku6wd9rp96kfxm64mgct3s3j26udp57dbu1.pqconnect.net"
        self.peer = Peer("131.155.69.126", "10.10.0.2", pkh=pkh, cname=cname)
        self.dumbcli = DummyClient()
        self.dumbdev = DummyDevice()
        self.handler = PQCClientConnectionHandler(
            self.peer,
            self.dumbdev,
            self.dumbcli,
        )

    def test__resolve_keyserver_address(self) -> None:
        """Tests that the keyserver ip and port are successfully obtained from
        a keyserver TXT record

        """
        self.handler._resolve_keyserver_address()
        self.assertEqual(
            self.handler._peer.get_external_ip(), "131.155.69.126"
        )
        self.assertEqual(self.handler._peer.get_keyport(), 42425)

    def test_get_static_key(self) -> None:
        logger.setLevel(9)
        self.handler._resolve_keyserver_address()
        self.assertTrue(self.handler._request_static_keys_paced())

    def test_get_ephemeral_key(self) -> None:
        logger.setLevel(9)
        self.handler._resolve_keyserver_address()
        self.assertTrue(self.handler._request_ephemeral_keys())

    def test_initiate_handshake_0rtt(self) -> None:
        pass


if __name__ == "__main__":
    main()
