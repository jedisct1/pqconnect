import os
import unittest
from time import monotonic, sleep

from pqconnect.common.crypto import KLEN
from pqconnect.common.util import round_timestamp
from pqconnect.cookie.cookie import Cookie
from pqconnect.cookie.cookiemanager import CookieManager
from pqconnect.tunnel import TunnelSession


class TestCookieManager(unittest.TestCase):
    def setUp(self) -> None:
        self.session_key = b"\x00" * KLEN
        self.seed = b"\x00" * KLEN
        self.cm = CookieManager(self.session_key, self.seed)
        sleep(0.01)

    def tearDown(self) -> None:
        pass

    def test__update_deterministic(self) -> None:
        timestamp = 0
        orig_len = len(self.cm._keystore)
        self.cm._update_deterministic(timestamp, b"\x00" * KLEN)
        self.assertEqual(len(self.cm._keystore), orig_len + 1)
        key, nonce = self.cm.get_cookie_key(timestamp)
        self.assertEqual(
            key,
            (
                b"A\xa5}\x96\xbe\x82<ye\xee\xf0\x03\xa37\x03\xc2\xab\xde"
                b"\xa5\x8ex\x1c\xb4\xfb\x8a'\xb2\xd5\x07\xc7\xde\xa8"
            ),
        )

    def test__delete_cookie_key(self) -> None:
        pass

    def test_increment_nonce(self) -> None:
        now = round_timestamp(monotonic())

        self.cm._update()
        self.assertIsNotNone(self.cm._keystore[now])

        old_ctr = self.cm._keystore[now]["ctr"]
        self.cm._increment_nonce(now)
        self.assertEqual(old_ctr + 1, self.cm._keystore[now]["ctr"])

    def test_get_cookie_key(self) -> None:
        now = round_timestamp(monotonic())

        self.cm._update()
        key, _ = self.cm.get_cookie_key(now)
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), KLEN)

    def test_cookie_correctness(self) -> None:
        tid = os.urandom(32)
        t1_send_root = os.urandom(32)
        t1_recv_root = os.urandom(32)

        t2_send_root = bytes(
            [t1_recv_root[i] for i in range(len(t1_recv_root))]
        )
        t2_recv_root = bytes(
            [t1_send_root[i] for i in range(len(t1_send_root))]
        )
        # local state
        tun1 = TunnelSession(tid, t1_send_root, t1_recv_root)

        # remote state
        tun2 = TunnelSession(tid, t2_send_root, t2_recv_root)

        self.assertEqual(
            tun1.tunnel_recv(tun2.tunnel_send(b"hello")), b"hello"
        )
        # generate cookie and delete local state
        self.cm.start()
        sleep(0.01)
        key, nonce = self.cm.get_cookie_key()
        print("baking cookies")
        cookie: Cookie = tun1.to_cookie(key, nonce)
        print("cookies are ready")
        self.assertIsNotNone(cookie)

        tun1.close()
        del tun1

        # send cookie remotely, peer updates local state
        tun2.send_epoch_ratchet()
        tun2.recv_epoch_ratchet()

        # we get the cookie back, recreate state
        new_tun = self.cm.check_cookie(cookie.bytes())
        self.assertIsNotNone(new_tun)

        for _ in range(10):
            self.assertEqual(
                new_tun.tunnel_recv(tun2.tunnel_send(b"hello")), b"hello"
            )

        # close tunnels to kill running threads
        tun2.close()
        new_tun.close()
        self.cm.stop()
