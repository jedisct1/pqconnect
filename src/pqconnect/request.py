from struct import pack, unpack_from
from typing import Dict, List, Optional, Union

from pqconnect.common.constants import (
    EPHEMERAL_KEY_REQUEST,
    EPHEMERAL_KEY_RESPONSE,
    SEG_LEN,
    STATIC_KEY_REQUEST,
    STATIC_KEY_RESPONSE,
)
from pqconnect.common.crypto import dh, ekem, skem
from pqconnect.keys import PKTree
from pqconnect.log import logger

_pk, _ = skem.keypair()
_ecc, _ = dh.dh_keypair()
_mock_tree = PKTree(_pk, _ecc)


class UnpackException(Exception):
    """Raised when a request cannot be unpacked"""


class UnexpectedRequestException(Exception):
    """Raised if an unpacked request has the wrong number of fields or if
    fields have unexpected values

    """


class KeyRequest:
    """Base key request class that handles packing and unpacking of binary
    data. Correct parsing and validation of untrusted data is left to
    the subclasses.

    subclasses can be initialized either with specific attributes or with a
    blob that is later unpacked

    """

    def __init__(
        self, msg_type: bytes, payload: Optional[bytes] = None
    ) -> None:
        if not isinstance(msg_type, bytes):
            raise TypeError

        self._msg_type = msg_type
        self._payload: Optional[bytes] = payload

    def _pack_bts(self, bytestrs: list[bytes]) -> None:
        """Takes a list of bytestrings and sets payload to: msg_type ||
        len(bytestring_0) || bytestring_0 || ... || len(bytestring_n) ||
        bytestring_n

        Example:
        >>> from pqconnect.request import KeyRequest
        >>> req = KeyRequest(bytes.fromhex('0001'))
        >>> req._pack_bts([b"hello", b"goodbye"])
        >>> assert req.payload == bytes.fromhex('00010005') + b'hello' + bytes.fromhex('0007') + b'goodbye'

        """

        if not self._payload is None:
            raise ValueError

        if not all(isinstance(bs, bytes) for bs in bytestrs):
            raise TypeError

        self._payload = b"".join(
            [self._msg_type] + [pack("!H", len(bs)) + bs for bs in bytestrs]
        )

    def _pack(self) -> None:
        raise NotImplementedError

    def _unpack_bts(self) -> list[bytes]:
        """Takes a bytestring and parses individual fields from the length
        prepending each field. Returns them in a list.

        """
        if not self._payload:
            raise UnpackException

        bs = self._payload[len(STATIC_KEY_REQUEST) :]
        ret = []
        while bs:
            # Length value is 2 bytes
            if len(bs) < 2:
                raise UnpackException
            (l,) = unpack_from("!H", bs[:2])

            # Length should be >0
            if l <= 0:
                raise UnpackException

            # There should be at least l bytes left
            bs = bs[2:]
            if l > len(bs):
                raise UnpackException

            ret.append(bs[:l])
            bs = bs[l:]

        return ret

    def _unpack(self) -> None:
        pass

    @property
    def payload(self) -> bytes:
        """Returns the payload of this request as bytes"""
        if self._payload is None:
            raise AttributeError

        return self._payload

    def __bytes__(self) -> bytes:
        return self.payload


class StaticKeyRequest(KeyRequest):
    """Request type for static key packet requests

    Example:
    >>> from pqconnect.request import StaticKeyRequest, STATIC_KEY_REQUEST
    >>> req0 = StaticKeyRequest(depth=2, pos=5)
    >>> req_bytes = req0.payload
    >>> assert req_bytes[:2] == STATIC_KEY_REQUEST

    >>> req1 = StaticKeyRequest(payload=req_bytes)
    >>> assert req1.depth == 2
    >>> assert req1.pos == 5
    """

    def __init__(
        self,
        depth: Optional[int] = None,
        pos: Optional[int] = None,
        payload: Optional[bytes] = None,
    ):
        self._struct = PKTree().get_structure()

        super().__init__(msg_type=STATIC_KEY_REQUEST, payload=payload)

        if payload is not None and (depth is not None or pos is not None):
            raise TypeError

        if payload:
            self._unpack()

        elif depth is not None and pos is not None:
            if not isinstance(depth, int):
                raise TypeError

            if not isinstance(pos, int):
                raise TypeError

            if depth not in self._struct.keys() or pos not in range(
                0, self._struct[depth]
            ):
                raise ValueError

            self._depth = depth
            self._pos = pos
            self._pack()

    def _pack(self) -> None:
        """Generates request payload for the static key request"""
        if self._depth is None or self._pos is None:
            raise TypeError

        super()._pack_bts(
            [
                int.to_bytes(self._depth, 1, "little"),
                int.to_bytes(self._pos, 2, "little"),
                b"\x00" * len(_mock_tree.get_node(self._depth, self._pos)),
            ]
        )

    def _unpack(self) -> None:
        """Parse values from packet payload"""
        if not self._payload:
            raise AttributeError

        u = super()._unpack_bts()
        if len(u) != 3:
            raise UnpackException
        self._depth = int.from_bytes(u[0], "little")
        self._pos = int.from_bytes(u[1], "little")

    @property
    def depth(self) -> int:
        if self._depth is None:
            raise AttributeError

        return self._depth

    @property
    def pos(self) -> int:
        if self._pos is None:
            raise AttributeError
        return self._pos


class StaticKeyResponse(KeyRequest):
    """Response object containing a single packet of the static public key
    Merkle tree

    Example:
    >>> from pqconnect.request import StaticKeyResponse, STATIC_KEY_RESPONSE
    >>> resp0 = StaticKeyResponse(depth=1, pos=0, keydata=bytes.fromhex('00' * 32))
    >>> payload = resp0.payload
    >>> assert payload[:2] == STATIC_KEY_RESPONSE

    >>> resp1 = StaticKeyResponse(payload=payload)
    >>> assert resp1.depth == 1
    >>> assert resp1.pos == 0
    >>> assert resp1.keydata == bytes.fromhex('00' * 32)
    """

    def __init__(
        self,
        payload: Optional[bytes] = None,
        depth: Optional[int] = None,
        pos: Optional[int] = None,
        keydata: Optional[bytes] = None,
    ):
        self._struct = PKTree().get_structure()

        super().__init__(STATIC_KEY_RESPONSE, payload)

        # can either have payload OR (depth & pos & keydata)
        if payload and (depth or pos or keydata):
            raise TypeError

        elif payload:
            self._unpack()

        else:
            # Check types
            if not isinstance(depth, int):
                raise TypeError
            elif not isinstance(pos, int):
                raise TypeError
            elif not isinstance(keydata, bytes):
                raise TypeError

            # Check values
            elif depth not in self._struct.keys():
                raise ValueError
            elif pos not in range(0, self._struct[depth]):
                raise ValueError

            self._depth: int = depth
            self._pos: int = pos
            self._keydata: bytes = keydata
            self._pack()

    def _pack(self) -> None:
        """Creates payload from object values"""
        super()._pack_bts(
            [
                int.to_bytes(self._depth, 1, "little"),
                int.to_bytes(self._pos, 2, "little"),
                self._keydata,
            ]
        )

    def _unpack(self) -> None:
        """Populates object values from payload"""
        u = super()._unpack_bts()
        if len(u) != 3:
            raise UnexpectedRequestException

        self._depth = int.from_bytes(u[0], "little")
        if self._depth not in self._struct.keys():
            raise UnpackException

        self._pos = int.from_bytes(u[1], "little")
        if self._pos < 0 or self._pos >= self._struct[self._depth]:
            raise UnpackException

        self._keydata = u[2]
        if len(self._keydata) > SEG_LEN:
            raise UnpackException

    @property
    def depth(self) -> int:
        """Get depth"""
        return self._depth

    @property
    def pos(self) -> int:
        """Get packet index"""
        return self._pos

    @property
    def keydata(self) -> bytes:
        """Get packet data"""
        return self._keydata


class EphemeralKeyRequest(KeyRequest):
    """Request type for ephemeral keys"""

    def __init__(self) -> None:
        super().__init__(EPHEMERAL_KEY_REQUEST)
        super()._pack_bts(  # make request correct length
            [bytes(ekem.pklen), bytes(dh.lib25519_dh_PUBLICKEYBYTES)]
        )


class EphemeralKeyResponse(KeyRequest):
    """Response object containing server's ephemeral public keys"""

    def __init__(
        self,
        payload: Optional[bytes] = None,
        pqpk: Optional[bytes] = None,
        npqpk: Optional[bytes] = None,
    ):
        super().__init__(EPHEMERAL_KEY_RESPONSE, payload)

        if payload and (npqpk or pqpk):
            raise TypeError

        elif payload:
            self._unpack()

        else:
            if not isinstance(pqpk, bytes):
                raise TypeError

            if not isinstance(npqpk, bytes):
                raise TypeError

            if len(pqpk) != ekem.pklen:
                raise ValueError

            if len(npqpk) != dh.lib25519_dh_PUBLICKEYBYTES:
                raise ValueError

            self._pqpk = pqpk
            self._npqpk = npqpk
            self._pack()

    def _pack(self) -> None:
        super()._pack_bts([self._pqpk, self._npqpk])

    def _unpack(self) -> None:
        u = super()._unpack_bts()
        if len(u) != 2:
            raise UnpackException

        if len(u[0]) != ekem.pklen:
            raise UnpackException

        if len(u[1]) != dh.lib25519_dh_PUBLICKEYBYTES:
            raise UnpackException

        self._pqpk = u[0]
        self._npqpk = u[1]

    @property
    def pqpk(self) -> bytes:
        return self._pqpk

    @property
    def npqpk(self) -> bytes:
        return self._npqpk


class KeyRequestHandler:
    """Class to obtain a KeyRequest subclass from a request received on the
    wire

    """

    def __init__(self, data: bytes):
        self.payload = data

    def request(self) -> Optional[KeyRequest]:
        """Return a KeyRequest subclass from payload"""
        r: Optional[KeyRequest] = None
        t = self.payload[: len(STATIC_KEY_REQUEST)]

        if t == STATIC_KEY_REQUEST:
            r = StaticKeyRequest(payload=self.payload)

        elif t == EPHEMERAL_KEY_REQUEST:
            r = EphemeralKeyRequest()

        return r


class KeyResponseHandler:
    """Class to obtain a KeyRequest subclass from a request received on the
    wire

    """

    def __init__(self, data: bytes):
        self.payload = data

    def response(self) -> Union[EphemeralKeyResponse, StaticKeyResponse, None]:
        """Return a KeyRequest subclass from payload"""
        r: Union[EphemeralKeyResponse, StaticKeyResponse, None] = None
        t = self.payload[: len(STATIC_KEY_REQUEST)]

        try:
            if t == STATIC_KEY_RESPONSE:
                r = StaticKeyResponse(payload=self.payload)

            elif t == EPHEMERAL_KEY_RESPONSE:
                r = EphemeralKeyResponse(payload=self.payload)

            else:
                raise Exception
        except Exception:
            logger.exception("Invalid response received")
            return None

        return r
