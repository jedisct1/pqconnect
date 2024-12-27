from __future__ import annotations

from threading import Event, Thread
from time import time
from typing import Dict, Tuple

from SecureString import clearmem

from pqconnect.common.constants import (
    DAY_SECONDS,
    EPOCH_DURATION_SECONDS,
    EPOCH_TIMEOUT_SECONDS,
)
from pqconnect.common.crypto import dh, ekem
from pqconnect.common.util import round_timestamp
from pqconnect.log import logger


class EphemeralKey:
    """A simple class to store an ephemeral public key.
    ...

    Attributes
    __________
    x25519_pk: Curve25519 public key

    sntrup_pk: Streamlined NTRU Prime public key

    start: key timestamp, marking the time after which the key may be used. The
        key should only be distributed to users between start and start +
        EPOCH_DURATION_SECONDS.

    """

    def __init__(self, start: int, sntrup: bytes, x25519: bytes):
        if not isinstance(start, int):
            raise TypeError("start must be an int")
        self._start = start

        if not isinstance(sntrup, bytes):
            raise TypeError

        if len(sntrup) != ekem.pklen:
            raise ValueError("invalid sntrup key")

        self._sntrup_pk = sntrup

        if not isinstance(x25519, bytes):
            raise TypeError

        if len(x25519) != dh.lib25519_dh_PUBLICKEYBYTES:
            raise ValueError("invalid dh key")

        self._x25519_pk = x25519

    @property
    def start(self) -> int:
        """Returns the start timestamp"""
        return self._start

    def public_keys(self) -> Tuple[bytes, bytes]:
        """Returns the two public keys as (sntrup_pk, x25519_pk)"""
        return self._sntrup_pk, self._x25519_pk

    def get_secret_keys(self) -> Tuple[bytes, bytes]:
        raise NotImplementedError

    def copy(self) -> EphemeralKey:
        raise NotImplementedError

    def clear(self) -> None:
        raise NotImplementedError


class EphemeralPrivateKey(EphemeralKey):
    """A simple class to store an ephemeral private key and manage its
    erasure.
    ...

    Attributes
    __________
    x25519_pk: Curve25519 public key
    sntrup_pk: Streamlined NTRU Prime public key
    x25519_sk: Curve25519 private key
    sntrup_sk: Streamlined NTRU Prime private key
    start: int
        the integer timestamp in seconds since epoch after which the
        key can be used. The key should only be distributed to users
        between start and start + EPOCH_DURATION_SECONDS.
    """

    def __init__(
        self,
        start: int,
        sntrup_pk: bytes = b"",
        sntrup_sk: bytes = b"",
        x25519_pk: bytes = b"",
        x25519_sk: bytes = b"",
    ):
        if not (sntrup_pk and sntrup_sk):
            sntrup_pk, sntrup_sk = ekem.keypair()

        if not isinstance(sntrup_sk, bytes):
            raise TypeError

        if len(sntrup_sk) != ekem.sklen:
            raise ValueError("invalid sntrup key")

        self.sntrup_sk = sntrup_sk

        if not (x25519_pk and x25519_sk):
            x25519_pk, x25519_sk = dh.dh_keypair()

        if not isinstance(x25519_sk, bytes):
            raise TypeError

        if len(x25519_sk) != dh.lib25519_dh_SECRETKEYBYTES:
            raise ValueError("invalid x25519 key")

        self.x25519_sk = x25519_sk

        super().__init__(start, sntrup_pk, x25519_pk)

    def get_secret_keys(self) -> Tuple[bytes, bytes]:
        """Returns the two secret keys as (sntrup_sk, x25519_sk)"""
        return self.sntrup_sk, self.x25519_sk

    def copy(self) -> EphemeralKey:
        """returns a deep copy of this ephemeral private key"""
        sntrup_sk = bytes(
            [self.sntrup_sk[i] for i in range(len(self.sntrup_sk))]
        )
        x25519_sk = bytes(
            [self.x25519_sk[i] for i in range(len(self.x25519_sk))]
        )
        return EphemeralPrivateKey(
            self._start,
            sntrup_pk=self._sntrup_pk,
            sntrup_sk=sntrup_sk,
            x25519_pk=self._x25519_pk,
            x25519_sk=x25519_sk,
        )

    def clear(self) -> None:
        """Zeroes out memory of private keys"""
        clearmem(self.sntrup_sk)
        clearmem(self.x25519_sk)


class Keystore:
    """Base class to handle stores of a cache of ephemeral keys"""

    def __init__(self, string: str):
        self._store: Dict[int, EphemeralKey] = {}
        self._end_cond = Event()
        self._pruning_thread = Thread(target=self._prune_old_keys)
        self._string = string

    def add(self, key: EphemeralKey) -> None:
        """Adds the EphemeralKey key to the keystore"""
        idx = key.start
        self._store[idx] = key

    def delete(self, key: EphemeralKey) -> bool:
        """Deletes the EphemeralKey key from the keystore. If key is an
        EpehemeralPrivateKey, the key memory is zeroed before
        returning. Returns True if successful, otherwise False.

        """
        if key.start in self._store:
            try:
                _ = self._store.pop(key.start)
                return True
            except Exception:
                pass
        return False

    def start(self) -> None:
        """Start the pruning thread"""
        self._pruning_thread.start()

    def close(self) -> None:
        """Deletes all keys in the keystore"""
        self._end_cond.set()
        if self._pruning_thread.is_alive():
            logger.log(9, "joining keystore pruning thread")
            self._pruning_thread.join()
            logger.log(9, "keystore pruning thread joined")
        self._store.clear()

    def get_current_keys(self) -> EphemeralKey:
        """Returns the pair of currently valid ephemeral public keys in the
        keystore.

        """
        now = round_timestamp(time())
        # calling function should handle KeyError
        key = self._store[now]
        return key

    def get_store(self) -> Dict[int, EphemeralKey]:
        """Returns the dictionary holding the keys"""
        return self._store

    def _prune_old_keys(self, test: bool = False) -> None:
        """Housekeeping method to be run as a separate thread. Sleeps for
        EPOCH_DURATION_SECONDS and then deletes all ephemeral keys from the
        keystore that have expired.

        """
        while not self._end_cond.is_set():
            if test:
                self._end_cond.set()  # loop runs once and then exits
            self._end_cond.wait(timeout=EPOCH_DURATION_SECONDS)
            old_tss = []
            logger.debug(f"Pruning old keys from {self._string}")
            now = int(time())
            old = now - EPOCH_TIMEOUT_SECONDS
            for start_ts in self._store.keys():
                if start_ts < old:
                    old_tss.append(start_ts)
                else:
                    break

            for ts in old_tss:
                self.delete(self._store[ts])


class EphemeralPublicKeystore(Keystore):
    """Base class to handle stores of a cache of ephemeral public keys"""

    def __init__(self, store: dict):
        super().__init__("public store")
        for idx in store.keys():
            key = store[idx]
            ekem_pk, dh_pk = key.public_keys()
            new_key = EphemeralKey(idx, ekem_pk, dh_pk)
            self.add(new_key)

    def delete(self, key: EphemeralKey) -> bool:
        """Deletes the EphemeralKey key from the keystore. If key is an
        EpehemeralPrivateKey, the key memory is zeroed before
        returning. Returns True if successful, otherwise False.

        """
        if key.start in self._store:
            self._store.pop(key.start)
            return True
        return False

    def merge(self, remote_keystore: Keystore) -> None:
        "Copies all the keys from remote_keystore into our keystore"
        store = remote_keystore.get_store()
        for idx in store.keys():
            self.add(store[idx])

        # Stop the pruning thread in other keystore
        remote_keystore.close()


class EphemeralPrivateKeystore(Keystore):
    """Base class to handle stores of a cache of ephemeral private keys"""

    def __init__(self, start_time: int):
        super().__init__("private store")
        start = round_timestamp(start_time)
        for i in range(start, start + DAY_SECONDS, EPOCH_DURATION_SECONDS):
            key = EphemeralPrivateKey(i)
            self.add(key)

    def delete(self, key: EphemeralKey) -> bool:
        """Deletes the EphemeralKey key from the keystore. If key is an
        EpehemeralPrivateKey, the key memory is zeroed before
        returning. Returns True if successful, otherwise False.

        """
        if key.start in self._store:
            try:
                ephemeral_key = self._store.pop(key.start)
                ephemeral_key.clear()
                return True
            except Exception:
                pass
        return False

    def close(self) -> None:
        """Deletes all keys in the keystore"""
        for idx in self._store.keys():
            self._store[idx].clear()
        super().close()

    def get_public_keystore(self) -> EphemeralPublicKeystore:
        """Returns a copy of this keystore containing only the public keys"""
        return EphemeralPublicKeystore(self._store)

    def get_unexpired_keys(self) -> list[EphemeralKey]:
        """Returns list of all currently valid private keys in the
        keystore. This returns the actual key data, not the EphemeralPrivateKey
        object. For EPOCH_DURATION_SECONDS := 30 seconds and
        EPOCH_TIMEOUT_SECONDS := 120 seconds, this should yield four sets of
        ephemeral keys.

        """
        now = round_timestamp(time())
        ret = []
        for t in range(
            now, min(self._store.keys()) - 1, -EPOCH_DURATION_SECONDS
        ):
            try:
                ret.append(self._store[t])

            except Exception:
                continue

        return ret

    def merge(self, remote_keystore: "EphemeralPrivateKeystore") -> None:
        "Copies all the keys from remote_keystore into our keystore"
        store = remote_keystore.get_store()
        for idx in store.keys():
            remote_key = store[idx]
            new_key = remote_key.copy()
            self.add(new_key)

        # Stop the pruning thread in other keystore
        remote_keystore.close()
