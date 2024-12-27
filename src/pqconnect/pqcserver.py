import importlib.metadata
from ipaddress import ip_address
from multiprocessing.connection import Connection
from threading import Event, Lock, Thread
from time import monotonic as time
from typing import Dict, Optional, Tuple

from pqconnect.common.constants import (
    EPOCH_DURATION_SECONDS,
    EPOCH_TIMEOUT_SECONDS,
    INITIATION_MSG,
    PQCPORT,
)
from pqconnect.common.crypto import (
    NLEN,
    TAGLEN,
    dh,
    ekem,
    h,
    secret_unbox,
    skem,
)
from pqconnect.common.crypto import stream_kdf as kdf
from pqconnect.cookie.cookiemanager import CookieManager
from pqconnect.keystore import EphemeralPrivateKey, EphemeralPrivateKeystore
from pqconnect.log import logger
from pqconnect.peer import Peer
from pqconnect.tundevice import TunDevice
from pqconnect.tunnel import TunnelSession


class ReplayError(Exception):
    """Raised when a replayed handshake message is detected"""


class HandshakeError(Exception):
    """Raised when an invalid Handshake message is received"""


class PQCServer:
    """The PQCServer class handles handshake requests from clients.

    Attributes
    __________
    mceliece_sk: bytes
        The long term mceliece secret key
    x25519_sk: bytes
        The long term x25519 secret key
    session_key: bytes
        The long term symmetric session ticket encryption key
    keystore: EphemeralPrivateKeystore
        See class documentation
    version: str
        Current version
    device: TunDevice
        See class documentation

    """

    def __init__(
        self,
        mceliece_path: str,
        x25519_path: str,
        session_key_path: str,
        port: int,
        tun_conn: Connection,
        dev_name: str = "pqc0",
        host_ip: Optional[str] = None,
    ):
        try:
            logger.info("Starting PQConnect Server")
            logger.info("Loading static keys")

            with open(mceliece_path, "rb") as mceliece_sk:
                self.mceliece_sk = mceliece_sk.read()

            with open(x25519_path, "rb") as x25519_sk:
                self.x25519_sk = x25519_sk.read()

            with open(session_key_path, "rb") as session_key:
                self.session_key = session_key.read()
            logger.info("Static keys found")

        except FileNotFoundError:
            raise FileNotFoundError("Could not load static keys. Aborting...")

        self._keystore: Optional[EphemeralPrivateKeystore] = None
        self.version = importlib.metadata.version("pqconnect")

        # Condition variable to join threads
        self._end_cond = Event()

        # mutex for seen_mceliece_cts
        self._mut = Lock()

        self._cookie_manager = CookieManager(self.session_key)

        # To avoid handshake message replays, we keep a list of seen McEliece
        # ciphertexts from handshakes sent during the current ephemeral key
        # validity period. This gets cleaned periodically by a cleanup routine.

        self._seen_mceliece_cts: Dict[int, bytes] = dict()

        # XXX: checking for seen ct's means scanning whole dict. Probably
        # should reverse this, so the forgetting thread scans all entries every
        # 30 seconds to remove ones with old timestamps, and checking for
        # replays is O(1)

        self._forget_old_mceliece_cts_thread = Thread(
            target=self._forget_old_mceliece_cts
        )
        self._forget_old_mceliece_cts_thread.start()

        self._device = TunDevice(
            port,
            server=self,
            cookie_manager=self._cookie_manager,
            tun_conn=tun_conn,
            dev_name=dev_name,
            host_ip=host_ip,
        )

        self._device_thread = Thread(target=self._device.start)

    def set_keystore(self, keystore: EphemeralPrivateKeystore) -> None:
        """Adds the keys in keystore to the server's keystore"""
        # Since the lifetime of keys in the keystore will overlap the
        # transition from one keystore to the next, we don't simply replace the
        # keystore if it exists. We instead add new keys to the existing store.

        # This gets called from a different thread. However, Python native
        # structures are thread-safe, so we don't need to implement a lock
        # here.

        if not self._keystore:
            self._keystore = keystore
            self._keystore.start()
        else:
            self._keystore.merge(keystore)
        logger.debug("Keystore set")

    def complete_handshake(self, packet: bytes, addr: Tuple[str, int]) -> None:
        """"""
        if not isinstance(packet, bytes):
            raise TypeError("Invalid packet")

        if not (
            isinstance(addr, tuple)
            and isinstance(addr[0], str)
            and isinstance(addr[1], int)
        ):
            raise TypeError
        if not self._keystore:
            raise Exception("No keystore has been set")

        # Get current secret keys
        try:
            keys = self._keystore.get_unexpired_keys()
            if len(keys) == 0 or not all(
                [isinstance(k, EphemeralPrivateKey) for k in keys]
            ):
                raise Exception("No ephemeral keys available")
        except Exception:  # TODO
            pass

        # Create a connection object to complete handshake
        for eph_key in keys:
            sntrup, x25519 = eph_key.get_secret_keys()
            hs = PQCServerHS(
                self,
                self.mceliece_sk,
                self.x25519_sk,
                sntrup,
                x25519,
                packet,
                addr,
            )
            hs.start()

    def is_mceliece_ct_seen(self, mceliece_ct: bytes) -> bool:
        """Returns True if the given mceliece_ct has is in the collection of
        recently observed ciphertext values

        """
        return mceliece_ct in self._seen_mceliece_cts.values()

    def remember_mceliece_ct(self, mceliece_ct: bytes) -> None:
        """Stores a (timestamp,mceliece ciphertext) record from a successful
        handshake for future replay checks

        """
        with self._mut:
            if self.is_mceliece_ct_seen(mceliece_ct):
                raise ValueError(
                    "Cannot add the same mceliece ciphertext twice"
                )
            now = int(time())
            self._seen_mceliece_cts[now] = mceliece_ct

    def _forget_old_mceliece_cts(self) -> None:
        """Remove old handshake mceliece ciphertexts"""

        while not self._end_cond.is_set():
            self._end_cond.wait(timeout=EPOCH_DURATION_SECONDS)
            with self._mut:
                expired = []
                old = time() - EPOCH_TIMEOUT_SECONDS
                for ts in self._seen_mceliece_cts.keys():
                    if ts <= old:
                        expired.append(ts)

                for ts in expired:
                    del self._seen_mceliece_cts[ts]

    def add_new_connection(
        self, session: TunnelSession, addr: Tuple[str, int]
    ) -> bool:
        """Adds a new tunnel session to the monitor"""
        if session is None or not isinstance(session, TunnelSession):
            raise TypeError("TunnelSession is invalid")

        try:
            ip_address(addr[0])
            if not isinstance(addr[1], int) and addr[1] not in range(1 << 16):
                raise ValueError("Invalid port")
        except (ValueError, KeyError) as e:
            raise e

        internal_ip = self._device.get_next_ip()
        peer = Peer(addr[0], internal_ip)
        peer.set_tunnel(session)

        if addr[1] != PQCPORT:
            peer.set_pqcport(addr[1])

        return self._device.add_peer(peer)

    def start(self) -> None:
        """Starts the device monitor as a separate thread"""
        self._device_thread.start()

    def close(self) -> None:
        """Stops all threads and deletes"""
        logger.debug("Server stopping")
        self._end_cond.set()
        logger.log(9, "Joining device thread")
        if self._device_thread.is_alive():
            self._device_thread.join()
        logger.log(9, "Device thread joined")

        logger.log(9, "Joining forget_old_mceliece_cts thread")
        if self._forget_old_mceliece_cts_thread.is_alive():
            self._forget_old_mceliece_cts_thread.join()
        logger.log(9, "forget_old_mceliece_cts thread joined")

        self._device.close()
        if self._keystore:
            self._keystore.close()


class PQCServerHS(Thread):
    """When a new handshake message is received a PQCServerHS
    object is initiated to parse the handshake messages and complete
    the handshake.

    """

    def __init__(
        self,
        server: PQCServer,
        s_mceliece_sk: bytes,
        s_x25519_sk: bytes,
        e_sntrup_sk: bytes,
        e_x25519_sk: bytes,
        pkt: bytes,
        addr: Tuple[str, int],
    ):
        super().__init__()
        self.server = server
        self.s_mceliece_sk = s_mceliece_sk
        self.s_x25519_sk = s_x25519_sk
        self.e_sntrup_sk = e_sntrup_sk
        self.e_x25519_sk = e_x25519_sk
        self.pkt = pkt
        self.addr = addr

        self.handshake_state: bytes = b""
        self.cipher_state: bytes = b""

    def get_handshake_message_values(
        self, data: bytes
    ) -> tuple[bytes, bytes, bytes, bytes, bytes]:
        """Parses handshake message values from raw packet data."""
        try:
            idx = 0
            if not data[idx : idx + 2] == INITIATION_MSG:
                raise ValueError(
                    (
                        "Message is not a handshake message.",
                        "This shouldn't happen.",
                    )
                )

            idx += 2
            c0 = data[idx : idx + skem.CIPHERTEXTBYTES]
            idx += skem.CIPHERTEXTBYTES
            c1 = data[idx : idx + dh.lib25519_dh_PUBLICKEYBYTES]
            idx += dh.lib25519_dh_PUBLICKEYBYTES
            tag1 = data[idx : idx + TAGLEN]
            idx += TAGLEN
            c3 = data[idx : idx + ekem.clen]
            idx += ekem.clen
            tag3 = data[idx : idx + TAGLEN]
            idx += TAGLEN

        except IndexError:
            # we ran out of data during parsing
            raise IndexError("Handshake message is incomplete.")

        if len(data) != idx:
            raise IndexError("Handshake message has incorrect length.")

        return c0, c1, tag1, c3, tag3

    def complete_handshake_0rtt(
        self, c0: bytes, c1: bytes, tag1: bytes, c3: bytes, tag3: bytes
    ) -> TunnelSession:
        """Completes a 0-RTT handshake and if successful, returns a new Tunnel
        object.

        """
        # Decapsulate c0 store in cipher_state. Note, this will usually return
        # a value even if the ciphertext is invalid, but the handshake will
        # fail at the next step.
        try:
            self.cipher_state = skem.dec(c0, self.s_mceliece_sk)

        except Exception:
            raise ValueError("Failed to decapsulate c0")

        # Store c0 in handshake_state
        self.handshake_state = c0

        # decrypt c1*
        try:
            e_x25519_i = secret_unbox(
                self.cipher_state,
                b"\x00" * NLEN,
                tag1,
                c1,
                self.handshake_state,
            )

        except Exception as e:
            raise ValueError(f"Failed to decrypt client ephemeral key: {e}")

        self.handshake_state = h(self.handshake_state + c1 + tag1)

        (self.cipher_state,) = kdf(
            1, self.cipher_state, dh.dh(e_x25519_i, self.s_x25519_sk)
        )

        (self.cipher_state,) = kdf(
            1, self.cipher_state, dh.dh(e_x25519_i, self.e_x25519_sk)
        )

        try:
            c2 = secret_unbox(
                self.cipher_state,
                b"\x00" * NLEN,
                tag3,
                c3,
                self.handshake_state,
            )

        except Exception as e:
            raise ValueError(f"Failed to decrypt c3*: {e}")

        try:
            k3 = ekem.dec(c2, self.e_sntrup_sk)

        except Exception as e:
            raise ValueError(f"Failed to decapsulate c2: {e}")

        (self.cipher_state,) = kdf(1, self.cipher_state, k3)
        self.handshake_state = h(self.handshake_state + c3 + tag3)
        tid, ti, tr = kdf(3, self.cipher_state, self.handshake_state)

        return TunnelSession(tid, tr, ti)

    def shake_hands(self, data: bytes) -> TunnelSession:
        """Given raw packet data returns a Tunnel on success"""
        try:
            hs_values = self.get_handshake_message_values(data)
            logger.debug("Handshake initiation message parsed successfully.")

            # Check replay
            mceliece_ct = hs_values[0]
            if self.server.is_mceliece_ct_seen(mceliece_ct):
                raise ReplayError("Replay detected")

            session = self.complete_handshake_0rtt(*hs_values)

            # Remember mceliece_ct
            self.server.remember_mceliece_ct(mceliece_ct)
            logger.info("Handshake succeeded: New tunnel created")
            return session

        except IndexError as e:
            raise HandshakeError(e)

    def run(self) -> None:
        """Performs server handshake and establishes a new session if valid"""
        try:
            tun = self.shake_hands(self.pkt)
        except Exception as e:
            logger.exception(e)
            return

        if tun:
            self.server.add_new_connection(tun, self.addr)

            logger.debug(
                f"Tunnel with tID {tun.get_tid().hex()} \
            created successfully"
            )
