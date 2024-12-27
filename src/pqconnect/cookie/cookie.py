from __future__ import annotations

from struct import pack, unpack_from
from typing import Tuple

from ..common.constants import (
    COOKIE_PREFIX,
    COOKIE_PREFIX_LEN,
    TIDLEN,
    TIMESTAMP_LEN,
)
from ..common.crypto import NLEN, TAGLEN, secret_box

# PREFIX | TID_BYTES | NONCE | CT (TID, Epoch_BYTES, SND_ROOT, RCV_ROOT) | ATAG
COOKIE_LEN = (
    COOKIE_PREFIX_LEN
    + len(pack("!Q", 0))
    + NLEN
    + len(pack("!L", 0))
    + 3 * TIDLEN  # TID, SEND_ROOT, RECV_ROOT
    + TAGLEN
)


class InvalidCookieMsgException(Exception):
    """Raised when a cookie is malformed"""


class Cookie:
    def __init__(self, timestamp: int, nonce: bytes, ct: bytes, tag: bytes):
        self._timestamp: int = timestamp
        self._nonce: bytes = nonce
        self._ct: bytes = ct
        self._auth_tag: bytes = tag

    def timestamp(self) -> int:
        return self._timestamp

    def nonce(self) -> bytes:
        return self._nonce

    def ct(self) -> Tuple[bytes, bytes]:
        return self._ct, self._auth_tag

    @staticmethod
    def _parse_cookie_timestamp(bts: bytes) -> int:
        """Parse and return timestamp from a cookie packet"""
        try:
            (ts,) = unpack_from("!Q", bts, offset=COOKIE_PREFIX_LEN)

        except Exception as e:
            raise InvalidCookieMsgException from e

        return ts

    @staticmethod
    def _parse_cookie_nonce(bts: bytes) -> bytes:
        """Parse and return nonce from a cookie"""
        try:
            nonce = bts[
                COOKIE_PREFIX_LEN
                + TIMESTAMP_LEN : COOKIE_PREFIX_LEN
                + TIMESTAMP_LEN
                + NLEN
            ]

        except Exception as e:
            raise InvalidCookieMsgException from e

        return nonce

    @staticmethod
    def _parse_cookie_ct(bts: bytes) -> tuple[bytes, bytes]:
        """Parse and return cookie ciphertext and authentication tag"""
        try:
            ct = bts[COOKIE_PREFIX_LEN + TIMESTAMP_LEN + NLEN : -TAGLEN]
            tag = bts[-TAGLEN:]

        except Exception as e:
            raise InvalidCookieMsgException from e

        return ct, tag

    @classmethod
    def from_session_values(
        cls,
        key: bytes,
        nonce: bytes,
        timestamp: int,
        tid: bytes,
        epoch: int,
        send_chain_root: bytes,
        recv_chain_root: bytes,
    ) -> Cookie:
        """Creates a Cookie object from session values and a provided cookie
        key/nonce

        """
        if not all(
            isinstance(x, bytes)
            for x in [key, nonce, tid, send_chain_root, recv_chain_root]
        ):
            raise TypeError()

        if not all(isinstance(x, int) for x in [timestamp, epoch]):
            raise TypeError

        ts_bts = pack("!Q", timestamp)
        epoch_bts = pack("!L", epoch)
        ct, tag = secret_box(
            key,
            nonce,
            b"".join([tid, epoch_bts, send_chain_root, recv_chain_root]),
            ts_bts,
        )

        return cls(timestamp, nonce, ct, tag)

    @classmethod
    def from_bytes(cls, packet: bytes) -> Cookie:
        if not isinstance(packet, bytes):
            raise TypeError

        if len(packet) != COOKIE_LEN:
            raise InvalidCookieMsgException

        if packet[:COOKIE_PREFIX_LEN] != COOKIE_PREFIX:
            raise InvalidCookieMsgException

        timestamp = cls._parse_cookie_timestamp(packet)
        nonce = cls._parse_cookie_nonce(packet)
        ct, tag = cls._parse_cookie_ct(packet)

        return cls(timestamp, nonce, ct, tag)

    def bytes(self) -> bytes:
        """Returns a packed binary cookie blob to send over the network"""
        ts_bts = pack("!Q", self._timestamp)
        return b"".join(
            [COOKIE_PREFIX, ts_bts, self._nonce, self._ct, self._auth_tag]
        )
