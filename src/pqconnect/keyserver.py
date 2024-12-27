from __future__ import annotations

from socket import AF_INET, SOCK_DGRAM, socket
from sys import exit as bye
from threading import Event, Thread
from typing import Optional, Union

from pqconnect.common.constants import (
    KEYPORT,
    MCELIECE_PK_PATH,
    X25519_PK_PATH,
)
from pqconnect.keys import PKTree
from pqconnect.keystore import EphemeralKey, EphemeralPublicKeystore
from pqconnect.log import logger
from pqconnect.request import (
    EphemeralKeyRequest,
    EphemeralKeyResponse,
    KeyRequestHandler,
    StaticKeyRequest,
    StaticKeyResponse,
)


class KeyServer(Thread):
    """Simple request/response server over UDP"""

    def __init__(
        self,
        mceliece_pk_path: str = MCELIECE_PK_PATH,
        x25519_pk_path: str = X25519_PK_PATH,
        keyport: int = KEYPORT,
    ) -> None:
        super().__init__()
        self._end_cond = Event()
        self._keystore: Optional[EphemeralPublicKeystore] = None
        self._port = keyport
        try:
            self._pktree = PKTree.from_file(mceliece_pk_path, x25519_pk_path)
        except FileNotFoundError as e:
            logger.exception(e)
            bye(1)
        self._transport = socket(AF_INET, SOCK_DGRAM)
        self._transport.bind(("0.0.0.0", self._port))

    def set_keystore(self, keystore: EphemeralPublicKeystore) -> None:
        """sets the keystore"""
        if not self._keystore:
            self._keystore = keystore
            self._keystore.start()
        else:
            self._keystore.merge(keystore)

    def close(self) -> None:
        """Stopes the pruning thread, closes the listening socket, and deletes
        all keys in the keystore

        """
        self._end_cond.set()

        # transport socket is blocking
        sock = socket(AF_INET, SOCK_DGRAM)
        sock.sendto(b"", ("0.0.0.0", self._port))
        sock.close()

        self._transport.close()
        if self._keystore:
            self._keystore.close()

    def ephemeral_key_response(
        self, req: EphemeralKeyRequest
    ) -> EphemeralKeyResponse:
        if not self._keystore:
            raise AttributeError
        eph_key = self._keystore.get_current_keys()
        pq, npq = eph_key.public_keys()
        r = EphemeralKeyResponse(pqpk=pq, npqpk=npq)
        if len(bytes(req)) == len(bytes(r)):
            return r
        raise ValueError

    def static_key_response(self, req: StaticKeyRequest) -> StaticKeyResponse:
        depth = req.depth
        pos = req.pos
        keydata = self._pktree.get_node(depth, pos)
        r = StaticKeyResponse(depth=depth, pos=pos, keydata=keydata)
        if len(bytes(r)) == len(bytes(req)):
            return r
        raise ValueError

    def run(self) -> None:
        """Run the keyserver"""

        logger.info("Starting Keyserver")
        while not self._end_cond.is_set():
            data, addr = self._transport.recvfrom(4096)

            logger.info(f"Request received from {addr}.")

            # Get request type
            r = KeyRequestHandler(data).request()
            if not r:
                logger.error("Invalid request received.")
                continue

            # Handle ephemeral key request
            if type(r) == EphemeralKeyRequest and self._keystore:
                try:
                    response: Union[
                        StaticKeyResponse, EphemeralKeyResponse
                    ] = self.ephemeral_key_response(r)

                except Exception:
                    logger.exception(
                        f"Invalid ephemeral key request from {addr}"
                    )
                    continue

            # Handle static key request
            elif type(r) == StaticKeyRequest:
                try:
                    logger.debug(
                        f"Sending static key segment ({r.depth}, {r.pos})"
                    )
                    response = self.static_key_response(r)

                except ValueError:
                    logger.exception(f"Invalid static key request fron {addr}")
                    continue

            # Unknown request type
            else:
                continue

            logger.debug(f"Sending {type(r)} to {addr}")
            self._transport.sendto(response.payload, addr)
