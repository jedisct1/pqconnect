from struct import pack, unpack_from
from threading import Event, Lock, Thread
from time import monotonic
from typing import Optional

from SecureString import clearmem

from ..common.constants import (
    COOKIE_PREFIX,
    COOKIE_PREFIX_LEN,
    EPOCH_DURATION_SECONDS,
    EPOCH_TIMEOUT_SECONDS,
    TIDLEN,
)
from ..common.crypto import KLEN, NLEN, randombytes, secret_unbox, stream_kdf
from ..common.util import round_timestamp
from ..log import logger
from ..tunnel import TunnelSession
from .cookie import Cookie


class TimestampError(Exception):
    """Called when an invalid or non-existant timestamp is encountered"""


class ExhaustedNonceSpaceError(Exception):
    """Called in the unlikely event that we have exhausted the noncespace for a
    particular cookie key

    """


class CookieManager:
    """CookieManager creates, verifies, decrypts, and updates keys for session
    cookies. When the server has too many connections, it can store its state
    with a given client as a cookie and send it to the client, encrypted under
    the current epoch's cookie key.

    This is simply a mechanism for outsourcing state and is not meant to
    protect against abuse by malicious clients.

    When the client wishes to resume communication with the server it sends its
    cookie to the server, and the server will reconstruct its state with the
    client if the cookie is valid.

    """

    def __init__(self, master_cookie_key: bytes, seed: bytes = b""):
        self._keystore: dict[int, dict] = dict()

        # include seed as a parameter to make it testable
        if not seed:
            seed = randombytes(KLEN)
        (self._state,) = stream_kdf(1, master_cookie_key, seed)
        self._end_cond = Event()
        self._mut = Lock()
        self._update_thread = Thread(target=self._run_update)

    def _delete_cookie_key(self, timestamp: int) -> bool:
        """Erases key in the keystore with the given timestamp. Calling
        function is responsible for acquiring mutex. Returns True if key
        successfully deleted.

        """
        try:
            clearmem(self._keystore[timestamp]["key"])
            del self._keystore[timestamp]

        except KeyError:
            logger.exception("timestamp not found.")
            return False

        return True

    def _update_deterministic(self, timestamp: int, randomness: bytes) -> None:
        """Deterministic update function. Should be thread-safe without the
        mutex but adding just to be sure.

        """

        # Add new cookie key for this epoch, using both the last key and
        # new randomness as input to the KDF
        with self._mut:
            if timestamp not in self._keystore.keys():
                (self._state,) = stream_kdf(1, self._state, randomness)
                new_key = bytes([a for a in self._state])

                # store cookie key along with a counter nonce
                self._keystore[timestamp] = {"key": new_key, "ctr": 0}

            # Delete cookie keys for expired epochs
            old_tss = []
            for ts in self._keystore.keys():
                if ts < (timestamp - EPOCH_TIMEOUT_SECONDS):
                    old_tss.append(ts)

            for ts in old_tss:
                self._delete_cookie_key(ts)

    def _update(self) -> None:
        """Updates the current cookie key and deletes expired keys"""
        now = round_timestamp(monotonic())
        new_randomness = randombytes(KLEN)

        self._update_deterministic(now, new_randomness)

    def _increment_nonce(self, ts: int) -> None:
        """Increments the counter nonce for the given epoch's cookie
        key. Should only be called after acquiring mutex.

        """
        # make sure ts is a valid ts, otherwise
        if ts != round_timestamp(ts):
            raise TimestampError

        # Check if we've somehow issued too many cookies under this key
        if (self._keystore[ts]["ctr"] + 1) >= (1 << (NLEN)):
            raise ExhaustedNonceSpaceError

        self._keystore[ts]["ctr"] += 1

    def get_cookie_key(self, ts: Optional[int] = None) -> tuple[bytes, bytes]:
        """Returns the key stored for the given timestamp as well as the
        current nonce. Raises a ValueError if the key does not exist.

        """
        if ts is None:
            ts = round_timestamp(monotonic())

        else:
            ts = round_timestamp(ts)

        try:
            with self._mut:
                key = self._keystore[ts]["key"]
                nonce = self._keystore[ts]["ctr"].to_bytes(NLEN, "big")
                self._increment_nonce(ts)

        except KeyError as e:
            raise ValueError(f"Invalid timestamp") from e

        return key, nonce

    def _run_update(self) -> None:
        """Runs the _update method every EPOCH_DURATION_SECONDS seconds until
        the cv is set (by calling the stop method).

        """

        while not self._end_cond.is_set():
            self._update()
            self._end_cond.wait(timeout=EPOCH_DURATION_SECONDS)

    def check_cookie(self, pkt: bytes) -> TunnelSession:
        """Verifies and decrypts the cookie if it exists, and returns the
        resulting TunnelSession along with remaining packet data if successful.

        """
        cookie = Cookie.from_bytes(pkt)

        ts = cookie.timestamp()
        ts_bts = pack("!Q", ts)

        # Get nonce
        nonce = cookie.nonce()

        # Get ciphertext
        ct, tag = cookie.ct()

        # Get cookie key and verify + decrypt
        try:
            key, _ = self.get_cookie_key(ts)
            pt = secret_unbox(key, nonce, tag, ct, ts_bts)

        except KeyError as e:
            raise TimestampError from e

        # Data has been verified and decrypted.
        tid = pt[:TIDLEN]
        pt = pt[TIDLEN:]
        (epoch,) = unpack_from("!L", pt)
        pt = pt[4:]
        send_root = pt[:KLEN]
        recv_root = pt[KLEN:]

        # Return tunnel along with remaining packet data
        return TunnelSession.from_cookie_data(tid, epoch, send_root, recv_root)

    @staticmethod
    def is_cookie(msg: bytes) -> bool:
        return msg[:COOKIE_PREFIX_LEN] == COOKIE_PREFIX

    def stop(self) -> None:
        """Stops the update thread"""
        self._end_cond.set()

        # delete the keys in the keystore
        to_delete = []
        with self._mut:
            for ts in self._keystore.keys():
                to_delete.append(ts)
            for ts in to_delete:
                self._delete_cookie_key(ts)
            self._keystore.clear()

    def start(self) -> None:
        """Starts the update thread to ratchet forward the cookie key for each
        new epoch.
        """
        self._update_thread.start()
