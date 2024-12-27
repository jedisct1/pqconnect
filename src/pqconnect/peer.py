from enum import Enum
from ipaddress import ip_address
from typing import Optional, Tuple

from .common.constants import COOKIE_PREFIX, KEYPORT, PQCPORT
from .log import logger
from .tunnel import TunnelSession


class PeerState(Enum):
    """State of a peer connection.
    NEW:
    handshake msg sent (client) -> ESTABLISHED
    handshake msg or cookie received, success (server) -> ESTABLISHED
    close -> CLOSED

    ESTABLISHED:
    transport message received, successfully decrypted -> ALIVE
    tunnel timeout -> EXPIRED
    handshake error message received (client) -> ERROR
    close -> CLOSED

    ALIVE:
    tunnel timeout -> EXPIRED
    close -> CLOSED

    """

    NEW = 1  # No connection attempted yet
    ESTABLISHED = 2  # Handshake complete but no message received
    ALIVE = 3  # Message successfully received by peer over channel
    EXPIRED = 4  # TunnelSession timed out, ready to remove
    CLOSED = 5  # Closed, ready to remove
    ERROR = 6  # Error


class Peer:
    """A Peer object holds and modifies the state of a given connection with a
    remote peer and calls the cryptographic functions for traffic with that
    peer.

    """

    def __init__(
        self,
        external_ip: str,
        internal_ip: str,
        pkh: bytes = b"",
        cname: str = "",
        mceliece_pk: bytes = b"",
        x25519_pk: bytes = b"",
        port: Optional[int] = None,
        keyport: Optional[int] = None,
    ):
        self._tunnel: Optional[TunnelSession] = None

        # validate ip addresses
        try:
            ip_address(external_ip)
            ip_address(internal_ip)
            self._external_ip = external_ip  # Encapsulating (outer) IP
            self._internal_ip = internal_ip  # Encapsulated (inner) IP

        except ValueError as e:
            raise e

        if pkh and not isinstance(pkh, bytes):
            raise TypeError("pkh must be a byte string")
        self._pkh = pkh  # public key hash (if they are a server)

        if cname and not isinstance(cname, str):
            raise TypeError("cname must be a string")
        self._cname = cname

        self._mceliece_pk = mceliece_pk
        self._x25519_pk = x25519_pk
        self._pqcport = port  # Encapsulating header port
        self._keyport = keyport
        self._cookie = b""

        # Initialize the state of the peer
        self._state = PeerState.NEW
        self._tid: bytes = b""

    def get_cname(self) -> str:
        """Returns the peer cname"""
        return self._cname

    def get_pkh(self) -> bytes:
        """Returns the public key hash"""
        return self._pkh

    def get_tid(self) -> bytes:
        """Returns the tunnel ID of the tunnel associated with this peer."""
        if not self._tid:
            raise AttributeError("Peer has no tid")

        return self._tid

    def get_state(self) -> PeerState:
        return self._state

    def is_alive(self) -> bool:
        """Returns True if the peer has an active connection"""
        if not self._tunnel:
            return False

        return self._state == PeerState.NEW or self._tunnel.is_alive()

    def error(self) -> None:
        """Sets the state to ERROR"""
        self._state = PeerState.ERROR

    def last_used(self) -> float:
        """Returns the last timestamp that we sent traffic to or received
        traffic from the peer. If no connection has been established with the
        peer it returns 0.

        This allows to sort peers by their most recent activity.

        """
        if self._tunnel:
            return self._tunnel.get_most_recent_timestamp()

        else:
            return 0

    def set_tunnel(self, tunnel: TunnelSession) -> None:
        """Associate the tunnel with this peer and update state."""
        self._tunnel = tunnel
        self._tid = tunnel.get_tid()
        self._state = PeerState.ESTABLISHED

    # external IP address
    def get_external_ip(self) -> str:
        """Returns this peer's external IP address"""
        return self._external_ip

    def set_external_ip(self, ip: str) -> None:
        """Sets the external ip address to `ip`"""
        if not isinstance(ip, str):
            raise ValueError("ip must be a string")

        self._external_ip = ip

    # internal IP address
    def get_internal_ip(self) -> str:
        """Returns this peer's internal IP address"""
        return self._internal_ip

    # pqcport
    def get_pqcport(self) -> Optional[int]:
        """Returns this peer's port number"""
        return self._pqcport

    def set_pqcport(self, port: int) -> None:
        """Sets this peer's port number"""
        if not (isinstance(port, int) and port in range(1 << 16)):
            raise ValueError("port is not a valid port number")

        self._pqcport = port

    # keyport
    def get_keyport(self) -> Optional[int]:
        return self._keyport

    def set_keyport(self, port: int) -> None:
        if not (isinstance(port, int) and port in range(1 << 16)):
            raise ValueError("port is not a valid port number")

        self._keyport = port

    def encrypt(self, pkt: bytes) -> bytes:
        """Encrypts pkt under the existing tunnel for this peer. If we have a
        cookie for this peer, the cookie is pre-pended to the ciphertext

        """
        cookie = b""

        if not self._tunnel:
            raise Exception("Cannot encrypt to peer. No tunnel exists")

        # include cookie if we have one
        if self._cookie:
            cookie = self._cookie
            self._cookie = b""

        return cookie + self._tunnel.tunnel_send(pkt)

    def decrypt(self, pkt: bytes) -> bytes:
        """Decrypts pkt under the existing tunnel for this peer. Raises an
        exception if no connection exists. Returns empty byte string and logs
        an error if decryption fails. If the message is a cookie then the
        cookie is stored.

        """

        if not self._tunnel:
            raise Exception("Cannot decrypt from peer. No tunnel exists")

        if not self._tunnel.is_alive():
            self._state = PeerState.EXPIRED
            return b""

        try:
            msg = self._tunnel.tunnel_recv(pkt)

        except Exception as e:
            logger.exception(f"Decryption failed: {e}")
            return b""

        self._state = PeerState.ALIVE

        # Set cookie for peer if sent by the server (this will only happen on
        # the client side, since only the server encrypts the cookie to the
        # client. The client sends back the cookie outside the tunnel, since at
        # that point the server has no decryption keys)
        if msg[: len(COOKIE_PREFIX)] == COOKIE_PREFIX:
            self._cookie = msg
            return b""
        else:
            return msg

    def close(self) -> None:
        """Sets the state to CLOSED and closes the tunnel object if it exists."""
        if self._tunnel:
            self._tunnel.close()
        self._state = PeerState.CLOSED
