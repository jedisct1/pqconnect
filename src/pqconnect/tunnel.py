from __future__ import annotations

from struct import pack, unpack_from
from threading import Lock, Timer
from time import monotonic
from typing import Dict, Optional

from SecureString import clearmem

from .common.constants import (
    CHAIN_KEY_NUM_PACKETS,
    COOKIE_PREFIX,
    EPOCH_DURATION_SECONDS,
    EPOCH_TIMEOUT_SECONDS,
    HDRLEN,
    MAX_CHAIN_LEN,
    MAX_EPOCHS,
    TIDLEN,
    TUNNEL_MSG,
)
from .common.crypto import NLEN, TAGLEN, secret_box, secret_unbox
from .common.crypto import stream_kdf as kdf
from .cookie.cookie import Cookie
from .log import logger


class ExpiredRatchetException(Exception):
    """Raised when an operation is called on an expired ratchet"""


class EpochRatchetException(Exception):
    """Raised when an event occurs that attempts to ratchet forward more than
    MAX_EPOCHS

    """


class PacketKey:
    """Object containing a key and its index data"""

    def __init__(self, epoch: int, ctr: int, key: bytes):
        self._epoch = epoch
        self._ctr = ctr
        self._key = key

    def get_epoch(self) -> int:
        return self._epoch

    def get_ctr(self) -> int:
        return self._ctr

    def get_key(self) -> bytes:
        return self._key


class EpochChain:
    """Single horizontal branch of the christmas tree.

    root_key: the root key of the epoch. This gets erased during construction
    epoch: the epoch number
    start: the timestamp when the epoch is created (default to now)

    _expire : Time after which a new epoch should be used
    _ctr : The index of the next packet key to be generated
    _packet_keys : The encryption/decryption keys for session packets
    _next_epoch_key : The root key of the subsequent EpochChain
    _next_chain_key : The next key used by the KDF to derive packet_keys.

    """

    def __init__(
        self, root_key: bytes, epoch: int, start: Optional[int] = None
    ):
        if start is None:
            start = int(monotonic())

        self._expire = start + EPOCH_DURATION_SECONDS
        self._epoch = epoch
        self._ctr = 0
        self._packet_keys: Dict[int, bytes] = {}

        next_epoch_key, next_chain_key = kdf(2, root_key)
        clearmem(root_key)

        self._next_epoch_key: bytes = next_epoch_key
        self._next_chain_key: bytes = next_chain_key

        # Create packet keys
        self.chain_ratchet()

    def _get_epoch_no(self) -> int:
        """Return the epoch number"""
        return self._epoch

    def get_expiration_time(self) -> int:
        return self._expire

    def chain_ratchet(self) -> None:
        """Using current chain key, generate stream consisting of a new chain
        key and CHAIN_KEY_NUM_PACKETS packet keys, immediately overwriting
        the current chain key for PFS.

        self.send_chain['ctr'] is always the associative array key of
        the next packet key to be generated.

        """
        # generate the first CHAIN_KEY_NUM_PACKETS packet keys from this
        # chain key and immediately overwrite the chain key with the
        # next key for PFS

        chain_key, *packet_keys = kdf(
            CHAIN_KEY_NUM_PACKETS + 1, self._next_chain_key
        )
        clearmem(self._next_chain_key)
        self._next_chain_key = chain_key

        # Add new keys to the key dictionary
        self._packet_keys |= dict(
            zip(
                range(self._ctr, self._ctr + CHAIN_KEY_NUM_PACKETS),
                packet_keys,
            )
        )

        # Update the ctr
        self._ctr += CHAIN_KEY_NUM_PACKETS

    def expired(self, now: Optional[int] = None) -> bool:
        """Returns whether the epoch has expired"""
        if not now:
            now = int(monotonic())
        return now > self._expire

    def get_next_epoch_key(self) -> bytes:
        """Returns the root key for the next epoch in the ratchet"""
        return self._next_epoch_key

    def get_packet_key(self, index: int) -> PacketKey:
        """Return the key at index `index` if it exists"""

        # Create more packet keys if existing ones have all been used
        if not len(self._packet_keys):
            self.chain_ratchet()

        try:
            # If the index is greater than the maximum paket index, ratchet
            # forward until bound
            while (
                index > max(self._packet_keys.keys())
                and len(self._packet_keys) < MAX_CHAIN_LEN
            ):
                self.chain_ratchet()
            key = self._packet_keys[index]

        except KeyError as e:
            raise ValueError from e

        return PacketKey(self._epoch, index, key)

    def get_next_chain_key(self) -> PacketKey:
        """Returns the next unused packet key."""
        if not len(self._packet_keys):
            self.chain_ratchet()

        min_ctr = min(self._packet_keys.keys())

        try:
            key = self.get_packet_key(min_ctr)

        except ValueError:
            logger.exception(f"No key with index {min_ctr} exists in ratchet")

        return key

    def delete_packet_key(self, packet_key: PacketKey) -> None:
        """Zeroes the key and removes it from the ratchet"""

        if packet_key.get_epoch() != self._epoch:
            # Fail closed: Can't remove it from the chain but can erase the
            # key object directly
            clearmem(packet_key.get_key())
            raise ValueError

        try:
            ctr = packet_key.get_ctr()
            key = self._packet_keys.pop(ctr)
            clearmem(key)

        except KeyError as e:
            raise ValueError from e

        finally:
            # This should be redundant if no exception was raised.
            clearmem(packet_key.get_key())

    def clear(self) -> None:
        """Erases all keys in the epoch"""
        clearmem(self._next_epoch_key)
        clearmem(self._next_chain_key)
        while len(self._packet_keys):
            _, key = self._packet_keys.popitem()
            clearmem(key)


class SendChain:
    """The key chain for sending packets"""

    def __init__(self, root_key: bytes, epoch: int = 0):
        self._epoch = epoch
        self._chain = EpochChain(root_key, self._epoch)

    def epoch_ratchet(self, now: Optional[int] = None) -> None:
        """Increments the epoch counter and sets the chain to a new EpochChain
        object rooted at the next epoch key. The old chain is then securely
        erased.

        """
        if not now:
            now = int(monotonic())

        self._epoch += 1
        chain = self._chain
        start_time = min(now, chain.get_expiration_time())
        key = chain.get_next_epoch_key()
        self._chain = EpochChain(key, self._epoch, start=start_time)
        chain.clear()

    def get_next_key(self) -> PacketKey:
        """Get the next packet key in the chain. If the epoch has expired, the
        chain ratchets forward to a new epoch and recurses.

        """
        if self._chain.expired():
            self.epoch_ratchet()
            return self.get_next_key()

        else:
            return self._chain.get_next_chain_key()

    def get_epoch_no(self) -> int:
        """Return the current epoch number"""
        return self._epoch

    def delete_packet_key(self, packet_key: PacketKey) -> None:
        """Securely erase the packet key and remove it from the chain."""
        try:
            self._chain.delete_packet_key(packet_key)
        except Exception:
            logger.exception("Could not delete")

    def clear(self) -> None:
        """Zero out all keys in the chain"""
        self._chain.clear()


class ReceiveChain(SendChain):
    """The key chain for receiving packets."""

    def __init__(self, root_key: bytes, epoch: int = 0):
        """Unlike the SendChain we maintain a dictionary of EpochChain objects,
        each of which has a timer thread that deletes it

        """
        self._epoch = epoch
        chain = EpochChain(root_key, self._epoch)
        self._chains: Dict[int, EpochChain] = {self._epoch: chain}
        self._deletion_timers: list = []
        self._mut = Lock()

        t = Timer(
            EPOCH_TIMEOUT_SECONDS,
            self.delete_expired_epoch,
            args=(self._epoch,),
        )
        self._deletion_timers.append(t)
        t.start()

    def get_chain_len(self) -> int:
        """Returns the number of non-expired epochs in the receive chain"""
        return len(self._chains)

    def epoch_ratchet(self, now: Optional[int] = None) -> None:
        """Create a new epoch object and add it to the receive chain. If the
        ratchet has expired it raises an error.

        """
        # Need to protect receive chain with mutex to avoid
        # concurrent access by main thread and deletion thread

        if not now:
            now = int(monotonic())

        with self._mut:
            if len(self._chains) == 0:
                raise ExpiredRatchetException

            chain = self._chains[self._epoch]
            next_epoch_key = chain.get_next_epoch_key()

            # Set the next start time to be the minimum of now (we're moving
            # the clock ahead), or the last epoch's expiration time. We allow
            # the epoch to expire earlier than planned but not later.
            start_time = min(now, chain.get_expiration_time())
            self._epoch += 1

            # Create a new chain, overwriting next_epoch_key in the process
            new_chain = EpochChain(
                next_epoch_key, self._epoch, start=start_time
            )

            self._chains[self._epoch] = new_chain

            # Create deletion timer for the next chain
            t = Timer(
                interval=(EPOCH_TIMEOUT_SECONDS),
                function=self.delete_expired_epoch,
                args=(self._epoch,),
            )
            self._deletion_timers.append(t)
            t.start()

    def get_packet_key(self, epoch: int, ctr: int) -> PacketKey:
        """Get the packet key from epoch `epoch` at index `ctr` in the
        ratchet.

        """
        # Ratchet forward to new epoch if needed
        while (
            epoch > max(self._chains.keys()) and len(self._chains) < MAX_EPOCHS
        ):
            self.epoch_ratchet()

        if epoch not in self._chains.keys():
            raise EpochRatchetException

        try:
            with self._mut:
                chain = self._chains[epoch]
                key = chain.get_packet_key(ctr)
                return key

        except KeyError as e:
            raise ValueError from e

        finally:
            if self._mut.locked():
                self._mut.release()

    def delete_expired_epoch(self, epoch_no: int) -> None:
        """Zero memory for and delete all keys in epoch `epoch_no`"""
        with self._mut:
            try:
                epoch = self._chains[epoch_no]
                epoch.clear()
                del self._chains[epoch_no]

            except KeyError:
                logger.exception(f"Epoch {epoch_no} does not exist")

    def delete_packet_key(self, packet_key: PacketKey) -> None:
        """Securely erase the packet key and remove it from the chain"""
        try:
            epoch = packet_key.get_epoch()
            self._chains[epoch].delete_packet_key(packet_key)
        except Exception:
            logger.exception("Could not delete key")

    def clear(self) -> None:
        """Zero and delete all remaining receive chains"""
        for timer in self._deletion_timers:
            timer.cancel()

        for key in self._chains.keys():
            self._chains[key].clear()

        # Delete the chains from the dictionary
        self._chains.clear()


class TunnelSession:
    """TunnelSession holds the cryptographic state of a connection with a
    remote peer. It performs encryption/decryption using symmetric keys and
    ensures fast key erasure

    """

    def __init__(
        self, tid: bytes, send_chain_key: bytes, recv_chain_key: bytes
    ):
        self._tid = tid
        self._mut = Lock()
        self._last_used = 0

        # Initialize send key chain
        self._send_chain = SendChain(send_chain_key)

        # Initialize receive key chain
        self._recv_chain = ReceiveChain(recv_chain_key)

    @classmethod
    def from_cookie_data(
        cls,
        tid: bytes,
        epoch: int,
        next_send_epoch_key: bytes,
        next_recv_epoch_key: bytes,
    ) -> TunnelSession:
        """Returns a new TunnelSession object from previous state"""
        # Create a dummy object. We need to create the send and receive chains
        # manually
        session = cls(tid, b"\x00" * 32, b"\x00" * 32)

        # delete the existing chains
        session._send_chain.clear()
        session._recv_chain.clear()

        # Instantiate send and receive chains from the root keys. The epoch
        # value function parameter was the epoch when these root keys were the
        # *next* epoch keys, so we increment the epoch value by 1 and it
        # becomes the current epoch.
        session._send_chain = SendChain(next_send_epoch_key, epoch=epoch + 1)
        session._recv_chain = ReceiveChain(
            next_recv_epoch_key, epoch=epoch + 1
        )

        return session

    def get_epoch(self) -> int:
        """Returns the current sending epoch of the session"""
        return self._send_chain.get_epoch_no()

    def send_epoch_ratchet(self) -> None:
        """Ratchet the send chain forward one epoch"""
        self._send_chain.epoch_ratchet()

    def recv_epoch_ratchet(self) -> None:
        """Ratchet the receive chain forward one epoch"""
        with self._mut:
            self._recv_chain.epoch_ratchet()

    def close(self) -> None:
        """Clear both send and receive chains"""
        with self._mut:
            self._send_chain.clear()
            self._recv_chain.clear()

    def get_most_recent_timestamp(self) -> int:
        """Returns the timestamp of the last successfully encryption/decryption
        operation

        """
        return self._last_used

    def is_alive(self) -> bool:
        """Returns True if there are unexpired keys in the receiving chain"""
        return self._recv_chain.get_chain_len() > 0

    def get_tid(self) -> bytes:
        """Returns the TID for the current session"""
        return self._tid

    def get_send_key(self) -> PacketKey:
        """Returns the next packet key in the send chain."""
        with self._mut:
            return self._send_chain.get_next_key()

    def get_recv_key(self, epoch: int, ctr: int) -> PacketKey:
        """Return the packet key with index (epoch, ctr) if it exists. Raises a
        ValueError if it does not exist.

        """
        try:
            key = self._recv_chain.get_packet_key(epoch, ctr)

        except (ValueError, EpochRatchetException):
            logger.exception(
                "Invalid receive key index requested. "
                f"Current epoch: {self.get_epoch()}. Request: {epoch}, {ctr}"
            )

        return key

    def tunnel_send(self, packet: bytes, now: Optional[int] = None) -> bytes:
        """Encrypt packet under the next packet key in the send chain"""
        if not now:
            now = int(monotonic())

        try:
            packet_key = self.get_send_key()

        except Exception:
            logger.exception(f"Could not get packet key")
            return b""

        epoch = packet_key.get_epoch()
        ctr = packet_key.get_ctr()
        key = packet_key.get_key()
        hdr = TUNNEL_MSG + self._tid + pack("!HI", epoch, ctr)
        enc, tag = secret_box(key, b"\x00" * NLEN, packet, hdr)

        # Update _last_used
        self._last_used = now

        # erase and delete the key from the send chain
        self._send_chain.delete_packet_key(packet_key)

        return b"".join([hdr, enc, tag])

    def tunnel_recv(
        self, encrypted_packet: bytes, now: Optional[int] = None
    ) -> bytes:
        """Decrypt the incoming packet and return the plaintext. If decryption
        fails, the method returns an empty string

        """
        if now:
            self._last_used = now

        else:
            self._last_used = int(monotonic())

        try:
            epoch, ctr = unpack_from(
                "!HI", encrypted_packet[len(TUNNEL_MSG) + TIDLEN :]
            )
            packet_key = self.get_recv_key(epoch, ctr)
            key = packet_key.get_key()
            msg = secret_unbox(
                key,
                b"\x00" * NLEN,
                encrypted_packet[-TAGLEN:],
                encrypted_packet[HDRLEN:-TAGLEN],
                encrypted_packet[:HDRLEN],
            )
            self._recv_chain.delete_packet_key(packet_key)

            if msg[: len(COOKIE_PREFIX)] == COOKIE_PREFIX:
                self.recv_epoch_ratchet()

        except Exception as e:
            logger.log(9, f"Tunnel decryption failed: {e}")
            return b""

        finally:
            while (
                self._recv_chain.get_epoch_no()
                > self._send_chain.get_epoch_no()
            ):
                self.send_epoch_ratchet()

        return msg

    def to_cookie(
        self, key: bytes, nonce: bytes, timestamp: Optional[int] = None
    ) -> Cookie:
        """Returns a cookie from the current session state and closes the
        session

        """

        if not timestamp:
            timestamp = int(monotonic())

        with self._mut:
            epoch = self._send_chain._epoch
            send_root = self._send_chain._chain._next_epoch_key
            recv_root = self._recv_chain._chains[epoch]._next_epoch_key
            cookie = Cookie.from_session_values(
                key, nonce, timestamp, self._tid, epoch, send_root, recv_root
            )

        self.close()
        return cookie
