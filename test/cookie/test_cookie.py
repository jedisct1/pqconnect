from struct import pack
from unittest import TestCase, main

from pqconnect.common.constants import COOKIE_PREFIX_LEN, TIDLEN
from pqconnect.common.crypto import KLEN, NLEN, secret_unbox
from pqconnect.cookie.cookie import Cookie, InvalidCookieMsgException


class TestCookie(TestCase):
    def setUp(self) -> None:
        self.cookie_key = b"\x00" * KLEN
        self.nonce = b"\x00" * NLEN
        self.timestamp = 0
        self.tid = b"\x00" * TIDLEN
        self.epoch = 0
        self.send_root = b"\x01" * KLEN
        self.recv_root = b"\x02" * KLEN

    def tearDown(self) -> None:
        pass

    def _check_cookie(self, cookie: Cookie) -> None:
        self.assertEqual(cookie.timestamp(), self.timestamp)
        self.assertEqual(cookie.nonce(), self.nonce)
        ct, tag = cookie.ct()
        ts_bts = pack("!Q", self.timestamp)
        try:
            secret_unbox(self.cookie_key, self.nonce, tag, ct, ts_bts)
        except Exception as e:
            self.assertTrue(False, f"could not decrypt ciphertext: {e}")

    def test_from_session_values(self) -> None:
        """Checks that Cookie object is successfully created from session
        values

        """
        cookie = Cookie.from_session_values(
            self.cookie_key,
            self.nonce,
            self.timestamp,
            self.tid,
            self.epoch,
            self.send_root,
            self.recv_root,
        )
        self._check_cookie(cookie)

    def test_from_bytes(self) -> None:
        """Tests that cookie can be successfully deserialized from bytes"""
        cookie = Cookie.from_session_values(
            self.cookie_key,
            self.nonce,
            self.timestamp,
            self.tid,
            self.epoch,
            self.send_root,
            self.recv_root,
        )
        goodbytes = cookie.bytes()

        try:
            new_cookie = Cookie.from_bytes(goodbytes)
            self._check_cookie(new_cookie)
        except Exception as e:
            self.assertTrue(False, e)

        badbytes = goodbytes[:-1]
        try:
            new_cookie = Cookie.from_bytes(badbytes)
            self.assertTrue(False)
        except InvalidCookieMsgException:
            self.assertTrue(True)

        badbytes = b"\x00" * COOKIE_PREFIX_LEN + goodbytes[COOKIE_PREFIX_LEN:]
        try:
            new_cookie = Cookie.from_bytes(badbytes)
            self.assertTrue(False)
        except InvalidCookieMsgException:
            self.assertTrue(True)

        notbytes = 42
        try:
            new_cookie = Cookie.from_bytes(notbytes)
            self.assertTrue(False)
        except TypeError:
            self.assertTrue(True)


if __name__ == "__main__":
    main()
