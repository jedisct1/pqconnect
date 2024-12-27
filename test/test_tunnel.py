from time import monotonic, sleep
from unittest import TestCase

from pqconnect.common.constants import (
    CHAIN_KEY_NUM_PACKETS,
    EPOCH_DURATION_SECONDS,
    MAX_CHAIN_LEN,
    MAX_EPOCHS,
)
from pqconnect.common.crypto import randombytes
from pqconnect.tunnel import (
    EpochChain,
    PacketKey,
    ReceiveChain,
    SendChain,
    TunnelSession,
)


class TestEpochChain(TestCase):
    """Test class for the Epoch Chain"""

    def setUp(self) -> None:
        self.now = int(monotonic()) - EPOCH_DURATION_SECONDS - 1
        self.root_key = randombytes(32)
        self.epochChain = EpochChain(self.root_key, 0, start=self.now)

    def test_delete_packet_key(self) -> None:
        """Tests that packet keys are securely erased and deleted from the
        chain

        """
        pk: PacketKey = self.epochChain.get_next_chain_key()
        self.epochChain.delete_packet_key(pk)
        self.assertEqual(pk.get_key(), b"\x00" * 32)

        try:
            self.epochChain.delete_packet_key(pk)
            self.assertTrue(False, "key was not removed from the chain")
        except ValueError:
            self.assertTrue(True)

    def test_chain_ratchet(self) -> None:
        """Tests that the chain state is correct after ratcheting"""
        next_chain_key = self.epochChain._next_chain_key
        self.assertNotEqual(next_chain_key, b"\x00" * 32)

        # assert that the counter is correct
        self.assertEqual(self.epochChain._ctr, CHAIN_KEY_NUM_PACKETS)
        self.assertEqual(
            len(self.epochChain._packet_keys), CHAIN_KEY_NUM_PACKETS
        )
        self.epochChain.chain_ratchet()
        self.assertEqual(self.epochChain._ctr, 2 * CHAIN_KEY_NUM_PACKETS)
        self.assertEqual(
            len(self.epochChain._packet_keys), 2 * CHAIN_KEY_NUM_PACKETS
        )

        # assert that the previous chain key has been erased during ratchet
        self.assertEqual(next_chain_key, b"\x00" * 32)

        # assert that the new chain key has been created
        next_chain_key = self.epochChain._next_chain_key
        self.assertNotEqual(next_chain_key, b"\x00" * 32)

    def test_get_packet_key(self) -> None:
        """Tests that get_packet_key returns the correct key in the chain"""
        key = self.epochChain.get_packet_key(0)
        self.assertEqual(key.get_ctr(), 0)

        key = self.epochChain.get_packet_key(1)
        self.assertEqual(key.get_ctr(), 1)

        key = self.epochChain.get_packet_key(50)
        self.assertEqual(key.get_ctr(), 50)

        try:
            key = self.epochChain.get_packet_key(1000)
            self.assertTrue(
                False,
                (
                    "Exception should be thrown due to too many"
                    " (> MAX_CHAIN_LEN) keys in the chain"
                ),
            )

        except ValueError:
            self.assertTrue(True)

    def test_get_next_key(self) -> None:
        """Tests that get_next_chain_key returns keys from the chain in order"""
        for i in range(100):
            key = self.epochChain.get_next_chain_key()
            self.assertEqual(key.get_ctr(), i)
            self.epochChain.delete_packet_key(key)

    def test_clear_chain(self) -> None:
        keys = []
        for i in range(MAX_CHAIN_LEN):
            keys.append(self.epochChain.get_packet_key(i))

        self.epochChain.clear()
        self.assertEqual(self.epochChain._next_chain_key, b"\x00" * 32)
        self.assertEqual(self.epochChain._next_epoch_key, b"\x00" * 32)
        for k in keys:
            self.assertEqual(k.get_key(), b"\x00" * 32)


class TestSendChain(TestCase):
    def setUp(self) -> None:
        self.root_key = b"3" * 32
        self.sendChain = SendChain(self.root_key)

    def test_epoch_ratchet(self) -> None:
        """Tests that the state is correct after an epoch ratchet occurs:
        - next_epoch_key is erased upon each epoch ratchet
        - epoch_no is correctly instantiated"""
        for i in range(100):
            self.assertEqual(self.sendChain.get_epoch_no(), i)
            next_epoch_key = self.sendChain._chain.get_next_epoch_key()
            next_chain_key = self.sendChain._chain._next_chain_key
            self.assertNotEqual(next_epoch_key, b"\x00" * 32)
            self.assertNotEqual(next_chain_key, b"\x00" * 32)
            self.sendChain.epoch_ratchet()
            self.assertEqual(next_epoch_key, b"\x00" * 32)
            self.assertEqual(next_chain_key, b"\x00" * 32)

    def test_expired_epoch_ratchet(self) -> None:
        """Tests that an epoch ratchet occurs if a key is requested after the
        ratchet expires

        """
        # artificially turn the clock back 3 epochs
        key = self.sendChain.get_next_key()
        self.assertEqual(key.get_epoch(), 0)

        for i in range(1, 6):
            self.sendChain._chain._expire -= EPOCH_DURATION_SECONDS + 1
            key = self.sendChain.get_next_key()
            self.assertEqual(key.get_epoch(), i)

    def test_correct_expire_after_ratchet(self) -> None:
        """When a new epoch begins the expiration time should be:

        min(
            (last epoch expiration time + EPOCH_DURATION_SECONDS),
            (now + EPOCH_DURATION_SECONDS)
        )

        This allows us to sync forward with a peer whose clock is faster than
        ours (causing us to ratchet early)

        For example, if epoch zero, E_0, started at T=0, then the expiration
        time of E_0, Expire_0, = EPOCH_DURATION_SECONDS (30). If at T=20, we
        get a message from E_1, we'll sync forward, ratcheting to E_1. To allow
        for the possibility that our clock is slow, we don't set Expire_1 to 60
        (Expire_0 + EPOCH_DURATION_SECONDS), but we instead set Expire_1 = 50.

        """
        now = int(monotonic())
        self.sendChain._chain._expire = now
        self.sendChain.epoch_ratchet()
        self.assertEqual(self.sendChain._epoch, 1)
        self.assertEqual(
            self.sendChain._chain._expire, now + EPOCH_DURATION_SECONDS
        )

        self.sendChain._chain._expire = 0
        self.sendChain.epoch_ratchet()
        self.assertEqual(self.sendChain._epoch, 2)
        self.assertEqual(self.sendChain._chain._expire, EPOCH_DURATION_SECONDS)


class TestReceiveChain(TestCase):
    def setUp(self) -> None:
        self.root_key = b"\x00" * 32
        self.recv_chain = ReceiveChain(self.root_key)

    def tearDown(self) -> None:
        self.recv_chain.clear()

    def test_delete_expired_epoch(self) -> None:
        """Tests that delete_expired_epoch"""
        self.assertEqual(self.recv_chain.get_chain_len(), 1)
        self.recv_chain.delete_expired_epoch(0)

        self.assertEqual(self.recv_chain.get_chain_len(), 0)

    def test_epoch_ratchet(self) -> None:
        """Tests that the state is correct after an epoch ratchet occurse:
        - the epoch counter is incremented
        - a new epochChain is added to the chain dictionary
        - a new deletion timer thread is added to the timer list"""
        chain_len = self.recv_chain.get_chain_len()
        epoch_no = self.recv_chain.get_epoch_no()
        timers_len = len(self.recv_chain._deletion_timers)
        self.recv_chain.epoch_ratchet()

        self.assertEqual(self.recv_chain.get_epoch_no(), epoch_no + 1)
        self.assertEqual(self.recv_chain.get_chain_len(), chain_len + 1)
        self.assertEqual(len(self.recv_chain._deletion_timers), timers_len + 1)

    def test_delete_packet_key(self) -> None:
        """Tests that packet keys are correctly deleted"""
        key = self.recv_chain.get_packet_key(1, 5)
        self.assertEqual(key.get_epoch(), 1)
        self.assertEqual(key.get_ctr(), 5)
        self.assertEqual(
            key.get_key(),
            (
                b"'D;o\xd8\xd3\x8a\xff\x8e\x1d\xec\x89\xf9q\xc5"
                b"\xe2\xa7\xfe\x8ex\xe8pq-R\x7fL\xb3\xa8\xed\xa3u"
            ),
        )
        self.recv_chain.delete_packet_key(key)
        self.assertEqual(key.get_key(), self.root_key)
        try:
            self.recv_chain.get_packet_key(1, 5)
            self.assertTrue(False, "packet key was not removed")
        except Exception:
            self.assertTrue(True)


class TestTunnelSession(TestCase):
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
        self.t1 = TunnelSession(self.tid, self.t1_send_root, self.t1_recv_root)
        self.t2 = TunnelSession(self.tid, self.t2_send_root, self.t2_recv_root)

    def tearDown(self) -> None:
        self.t1.close()
        self.t2.close()

    def test_get_tid(self) -> None:
        """Tests that tid is assigned correctly"""
        self.assertEqual(self.t1.get_tid(), self.tid)
        self.assertEqual(self.t2.get_tid(), self.tid)

    def test_get_send_key(self) -> None:
        """Tests that get_send_key returns keys and in the correct order"""
        key = self.t1.get_send_key()
        self.assertEqual(key.get_epoch(), 0)
        self.assertEqual(key.get_ctr(), 0)
        self.t1._send_chain.delete_packet_key(key)

        key = self.t1.get_send_key()
        self.assertEqual(key.get_epoch(), 0)
        self.assertEqual(key.get_ctr(), 1)
        self.t1._send_chain.delete_packet_key(key)
        self.t1.send_epoch_ratchet()

        key = self.t1.get_send_key()
        self.assertEqual(key.get_epoch(), 1)
        self.assertEqual(key.get_ctr(), 0)
        self.t1._send_chain.delete_packet_key(key)

    def test_send_receive(self) -> None:
        """This sends 1000 packets of random bytes in two different epochs and
        makes sure that the receiving tunnel successfully decrypts all
        packets

        """
        for _ in range(1000):
            msg = randombytes(50)
            self.assertEqual(
                self.t1.tunnel_recv(self.t2.tunnel_send(msg)),
                msg,
            )

        self.t1.send_epoch_ratchet()
        for _ in range(1000):
            msg = randombytes(612)
            self.assertEqual(
                self.t2.tunnel_recv(self.t1.tunnel_send(msg)),
                msg,
            )

        self.t1.send_epoch_ratchet()
        for _ in range(1000):
            msg = randombytes(612)
            self.assertEqual(
                self.t1.tunnel_recv(self.t2.tunnel_send(msg)),
                msg,
            )

    def test_packet_replay(self) -> None:
        """Tests that we cannot decrypt the same message twice"""
        msg = randombytes(128)
        data = self.t2.tunnel_send(msg)
        self.assertEqual(self.t1.tunnel_recv(data), msg)
        self.assertEqual(self.t1.tunnel_recv(data), b"")

    def test_out_of_order_packets(self) -> None:
        """Tests that packets received out of order are decryptable"""
        msg = randombytes(256)
        pkts = []
        for _ in range(MAX_EPOCHS):
            pkts.append(self.t1.tunnel_send(msg))
            self.t1.send_epoch_ratchet()

        while pkts:
            data = pkts.pop()
            self.assertEqual(self.t2.tunnel_recv(data), msg)

    def test_tunnel_from_cookie_data(self) -> None:
        """Tests that a tunnel recreated from previous state (recovered from a
        cookie) functions as expected.

        """
        tid = self.t1.get_tid()
        epoch = self.t1._send_chain.get_epoch_no()
        ts = int(monotonic())
        send_key = self.t1._send_chain._chain.get_next_epoch_key()
        send_key = bytes([send_key[i] for i in range(len(send_key))])
        recv_key = self.t1._recv_chain._chains[epoch].get_next_epoch_key()
        recv_key = bytes([recv_key[i] for i in range(len(recv_key))])

        msg = randombytes(1000)
        self.assertEqual(
            self.t1.tunnel_recv(self.t2.tunnel_send(msg)),
            msg,
            "t1 and t2 not working",
        )

        tun = TunnelSession.from_cookie_data(tid, epoch, send_key, recv_key)

        self.t2.recv_epoch_ratchet()
        self.t2.send_epoch_ratchet()

        for _ in range(1000):
            msg = randombytes(128)
            data = self.t2.tunnel_send(msg)
            self.assertEqual(tun.tunnel_recv(data), msg)

        tun.close()


class TestState(TestCase):
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
        self.tme = TunnelSession(
            self.tid, self.t1_send_root, self.t1_recv_root
        )
        self.tpeer = TunnelSession(
            self.tid, self.t2_send_root, self.t2_recv_root
        )

    def tearDown(self) -> None:
        self.tme.close()
        self.tpeer.close()

    def test_forward_sync(self) -> None:
        """Tests that when we receive a message from a later epoch than our
        current send epoch, we ratchet forward to that epoch.

        """
        msg = b"hello"
        start = int(monotonic())

        # Sanity check that things are set up correctly
        expire_0 = self.tme._send_chain._chain._expire
        self.assertEqual(expire_0, start + EPOCH_DURATION_SECONDS)

        self.assertEqual(self.tpeer._send_chain._epoch, 0)
        self.assertEqual(
            self.tme.tunnel_recv(self.tpeer.tunnel_send(msg)), msg
        )

        self.assertEqual(len(self.tme._recv_chain._chains), 1)

        # sanity check that epoch ratcheting actually does something
        sleep(1)
        old_expire = self.tpeer._send_chain._chain._expire
        self.tpeer.send_epoch_ratchet()
        new_expire = self.tpeer._send_chain._chain._expire
        self.assertNotEqual(old_expire, new_expire)
        self.assertEqual(self.tpeer._send_chain._chain._epoch, 1)
        self.assertEqual(
            self.tpeer._send_chain._chain._expire,
            start + 1 + EPOCH_DURATION_SECONDS,
        )

        # Send/recv msg from different epoch
        ct = self.tpeer.tunnel_send(msg)
        self.assertEqual(self.tme.tunnel_recv(ct), msg)

        # Check that local state is correct

        self.assertEqual(self.tme._send_chain._epoch, 1)
        self.assertEqual(len(self.tme._recv_chain._chains), 2)

        # Send a response in epoch 1
        msg = b"new message"
        self.assertEqual(
            self.tpeer.tunnel_recv(self.tme.tunnel_send(msg)), msg
        )

        self.assertEqual(self.tpeer._send_chain._epoch, 1)
