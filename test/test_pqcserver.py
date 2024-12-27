import logging
import os
import socket
import time
from multiprocessing import Pipe
from typing import Any, Callable, Dict
from unittest import TestCase
from unittest.mock import mock_open, patch

from pqconnect.common.constants import (
    EPHEMERAL_KEY_REQUEST,
    INITIATION_MSG,
    MCELIECE_PK_PATH,
    X25519_PK_PATH,
)
from pqconnect.common.crypto import dh, skem
from pqconnect.iface import create_tun_interface
from pqconnect.keys import PKTree
from pqconnect.keyserver import KeyServer
from pqconnect.keystore import EphemeralPrivateKeystore
from pqconnect.log import logger
from pqconnect.peer import Peer
from pqconnect.pqcclient import PQCClientConnectionHandler
from pqconnect.pqcserver import PQCServer
from pqconnect.request import EphemeralKeyRequest


def randombts(n: int) -> bytes:
    return os.urandom(n)


class PQCServerTest(TestCase):
    def setUp(self) -> None:
        # PQCServer requires keyfiles during init. Just create a tmp file and
        # assign the keys later to make this more portable

        self.tun_file = create_tun_interface(
            "pqc_test_server", "10.10.0.1", 16
        )
        self.tmpfilename: str = "/tmp/tmp-" + randombts(8).hex()
        self.local_conn, self.remote_conn = Pipe()
        with open(self.tmpfilename, "wb") as f:
            f.write(b"0" * 32)
        self.pqcserver = PQCServer(
            self.tmpfilename,
            self.tmpfilename,
            self.tmpfilename,
            12345,
            self.local_conn,
            dev_name="pqc_test_server",
        )
        self.mceliece_pk, self.mceliece_sk = skem.keypair()
        self.x25519_pk, self.x25519_sk = dh.dh_keypair()

        self.pktree = PKTree(self.mceliece_pk, self.x25519_pk)

        self.session_key = randombts(32)

        # bad OOP practice but thanks, Python :)
        self.pqcserver.mceliece_sk = self.mceliece_sk
        self.pqcserver.x25519_sk = self.x25519_sk
        self.pqcserver.session_key = self.session_key

        # Set up an ephemeral keystore
        private_keystore = EphemeralPrivateKeystore(time.time())
        public_keystore = private_keystore.get_public_keystore()

        def mmock_open(*args: list[Any], **kwargs: Dict[Any, Any]) -> Callable:
            if args[0] == MCELIECE_PK_PATH:
                return mock_open(read_data=self.mceliece_pk)(*args, **kwargs)
            elif args[0] == X25519_PK_PATH:
                return mock_open(read_data=self.x25519_pk)(*args, **kwargs)
            else:
                return mock_open

        with patch("builtins.open", mmock_open):
            self.keyserver = KeyServer()
        self.keyserver.set_keystore(public_keystore)
        self.keyserver.start()
        self.pqcserver.set_keystore(private_keystore)

        # Create a socket from which we send messages to the (key)server
        self.out_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.out_sock.settimeout(2.0)

    def tearDown(self) -> None:
        self.out_sock.close()
        self.keyserver.close()
        self.pqcserver.close()
        self.tun_file.close()
        os.remove(self.tmpfilename)

    def test_keyserver(self) -> None:
        logger.setLevel(logging.DEBUG)
        addr = ("localhost", 42425)
        request = EphemeralKeyRequest().payload
        self.out_sock.sendto(request, addr)
        data, _ = self.out_sock.recvfrom(4096)
        self.assertNotEqual(data, b"")

    def test_handshake_cannot_replay(self) -> None:
        """Submit the same handshake message twice, and assert that only one
        connection with the server is established"""

        p = Peer("1.2.3.4", "10.10.0.2", pkh=self.pktree.get_node(0, 0))

        ephemeral_pk = self.keyserver._keystore.get_current_keys()
        sntrup_pk, eph_ecc_pk = ephemeral_pk.public_keys()
        mceliece_ct = skem.enc(self.mceliece_pk)
        client_ctx = PQCClientConnectionHandler(
            p, None, DummyClient(), mceliece_ct
        )

        client_ctx._s_x25519_r = self.x25519_pk
        client_ctx._e_sntrup_r = sntrup_pk
        client_ctx._e_x25519_r = eph_ecc_pk

        hs_vals = client_ctx.initiate_handshake_0rtt()

        # close the tunnel so timers are cancelled
        tun = list(hs_vals)[-1]
        tun.close()

        hs_vals = list(hs_vals)[:-1]

        msg = INITIATION_MSG + b"".join(hs_vals)

        print("Initial handshake")
        self.pqcserver.complete_handshake(msg, ("1.2.3.4", 12345))

        time.sleep(0.1)

        self.assertTrue(
            self.pqcserver.is_mceliece_ct_seen(hs_vals[0]),
            "mceliece ct not stored correctly",
        )
        seen_time = list(self.pqcserver._seen_mceliece_cts.keys())[0]

        print("Replay handshake")
        self.pqcserver.complete_handshake(msg, ("1.2.3.4", 12345))

        time.sleep(0.1)
        self.assertEqual(
            len(self.pqcserver._seen_mceliece_cts.keys()),
            1,
            "seen mceliece ct unexpected length",
        )
        self.assertEqual(
            list(self.pqcserver._seen_mceliece_cts.keys())[0],
            seen_time,
            "seen mceliece ct unexpected timestamp",
        )


class DummyClient:
    def __init__(self) -> None:
        pass

    def generate_prekeys(self, a: bytes, b: bytes, c: bytes) -> bool:
        return True
