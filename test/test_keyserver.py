import io
import socket
from random import randint
from time import time
from typing import Any, Callable, Dict
from unittest import TestCase, main
from unittest.mock import mock_open, patch

from pqconnect.common.constants import MCELIECE_PK_PATH, X25519_PK_PATH
from pqconnect.common.crypto import dh, ekem, skem
from pqconnect.common.util import round_timestamp
from pqconnect.keys import PKTree
from pqconnect.keyserver import KeyServer
from pqconnect.keystore import (
    EphemeralKey,
    EphemeralPrivateKey,
    EphemeralPrivateKeystore,
    Keystore,
)
from pqconnect.request import (
    EphemeralKeyRequest,
    EphemeralKeyResponse,
    StaticKeyRequest,
    StaticKeyResponse,
)


class TestKeyServer(TestCase):
    def setUp(self) -> None:
        self._s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._priv_keystore = EphemeralPrivateKeystore(time())
        self._pub_keystore = self._priv_keystore.get_public_keystore()
        self._keyport = randint(1025, 1 << 16)

        def open_keyfiles(name: str, mode: str) -> io.BytesIO:
            spk, _ = skem.keypair()
            sdh, _ = dh.dh_keypair()
            if name == "mceliece":
                return io.BytesIO(spk)
            else:
                return io.BytesIO(sdh)

        with patch("builtins.open", new=open_keyfiles) as mock_thing:
            self._keyserver = KeyServer("mceliece", "x25519", self._keyport)
            self._keyserver.set_keystore(self._pub_keystore)
            self._keyserver.start()

    def tearDown(self) -> None:
        self._priv_keystore.close()
        self._pub_keystore.close()
        self._keyserver.close()
        self._s.close()

    def test_ephemeral_request_response(self) -> None:
        req = EphemeralKeyRequest()
        self._s.settimeout(1)
        self._s.sendto(bytes(req), ("localhost", self._keyport))
        data, _ = self._s.recvfrom(4096)
        ntru, ecc = self._pub_keystore.get_current_keys().public_keys()
        resp = EphemeralKeyResponse(pqpk=ntru, npqpk=ecc)
        self.assertEqual(data, bytes(resp))

    def test_static_request_response(self) -> None:
        tree = PKTree()
        for i in tree.get_structure().keys():
            for j in range(tree.get_structure()[i]):
                req = StaticKeyRequest(i, j)
                self._s.sendto(bytes(req), ("localhost", self._keyport))
                data, _ = self._s.recvfrom(4096)
                resp = StaticKeyResponse(payload=data)
                self.assertTrue(tree.insert_node(i, j, resp.keydata))


class TestEphemeralKey(TestCase):
    def setUp(self) -> None:
        self.privkey = EphemeralPrivateKey(int(time()))

    def tearDown(self) -> None:
        pass

    def test_clear(self) -> None:
        sntrup, ecc = self.privkey.get_secret_keys()
        self.assertNotEqual(sntrup, b"\x00" * len(sntrup))
        self.assertNotEqual(ecc, b"\x00" * len(ecc))

        self.privkey.clear()
        self.assertEqual(sntrup, b"\x00" * len(sntrup))
        self.assertEqual(ecc, b"\x00" * len(ecc))

    def test_copy(self) -> None:
        copy = self.privkey.copy()
        sntrup_a, ecc_a = self.privkey.get_secret_keys()
        sntrup_b, ecc_b = copy.get_secret_keys()
        self.assertEqual(sntrup_a, sntrup_b)
        self.assertEqual(ecc_a, ecc_b)

        self.privkey.clear()
        self.assertNotEqual(sntrup_b, sntrup_a)
        self.assertNotEqual(ecc_b, ecc_a)


class TestKeystore(TestCase):
    def setUp(self) -> None:
        self.keystore = Keystore("test")
        self.keystore.start()

    def tearDown(self) -> None:
        self.keystore.close()

    def test_add_current_keys(self) -> None:
        sntrup_pk, sntrup_sk = ekem.keypair()
        ecc_pk, ecc_sk = dh.dh_keypair()
        now = round_timestamp(time())
        key = EphemeralKey(now, sntrup_pk, ecc_pk)
        self.keystore.add(key)

        key2 = self.keystore.get_current_keys()
        self.assertEqual(key, key2)

    def test_prune_old_keys(self) -> None:
        sntrup_pk, sntrup_sk = ekem.keypair()
        ecc_pk, ecc_sk = dh.dh_keypair()
        key = EphemeralKey(0, sntrup_pk, ecc_pk)
        self.keystore.add(key)
        try:
            self.assertEqual(key, self.keystore.get_store()[0])
        except Exception:
            self.assertTrue(False)

        self.keystore._prune_old_keys(test=True)

        try:
            key = self.keystore.get_store()[0]
            self.assertTrue(False, "key shouldn't exist")
        except Exception:
            self.assertTrue(True)


class TestEphemeralPrivateKeystore(TestCase):
    def setUp(self) -> None:
        self.keystore = EphemeralPrivateKeystore(int(time()))

    def tearDown(self) -> None:
        self.keystore.close()

    def test_delete(self) -> None:
        now = round_timestamp(time())
        key = EphemeralPrivateKey(now)
        self.keystore.add(key)
        try:
            self.assertEqual(self.keystore.get_store()[now], key)
        except Exception:
            G
            self.assertTrue(False, "could not get key")

        self.assertTrue(self.keystore.delete(key))

        try:
            new_key = self.keystore.get_store()[now]
            self.assertEqual(key, new_key)
            self.assertTrue(False, "key should not exist")
        except KeyError:
            self.assertTrue(True)
        except Exception:
            self.assertTrue(False, "key should not exist")


if __name__ == "__main__":
    main()
