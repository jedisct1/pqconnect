import importlib.metadata
from grp import getgrnam
from os import (
    getegid,
    geteuid,
    getgid,
    getgroups,
    getuid,
    setgid,
    setgroups,
    setuid,
)
from pwd import getpwnam
from sys import exit as bye
from typing import Any, Callable

from pqconnect.log import logger

from .constants import EPOCH_DURATION_SECONDS


class ExistingNftableError(Exception):
    """Raised if a table already exists when we try to add it to nftables"""

    pass


class NftablesError(Exception):
    """Raised when an nftables operation cannot be performed"""

    pass


def run_as_user(user: str) -> Callable:
    """Parameterized decorator to run a function as another user. This changes
    the uid and gid for the entire interpreter process

    """

    def decorator(func: Callable) -> Callable:
        def wrapper(*args: Any) -> Callable:
            try:
                u = getpwnam(user)
                g = getgrnam(user)

                # Privilege separation
                setgroups([g.gr_gid])
                setgid(g.gr_gid)
                setuid(u.pw_uid)
                logger.warning(
                    f"Running as uid: {getuid()} euid: {geteuid()} "
                    + f"gid: {getgid()} euid: {getegid()} "
                    + f"groups: {getgroups()}"
                )

            except KeyError:
                logger.exception(
                    f"Privilege separation user {user} cannot be found."
                )
                bye(1)

            except PermissionError as e:
                logger.exception(
                    f"Unable to run as unprivileged user: {user}."
                )
                bye(1)

            return func(*args)

        return wrapper

    return decorator


def round_timestamp(timestamp: float) -> int:
    """Returns the given timestamp rounded down to the nearest epoch"""
    return int(timestamp // EPOCH_DURATION_SECONDS * EPOCH_DURATION_SECONDS)


def base32_encode(x: bytes) -> str:
    """Follows the base32 encoding used in DNScurve, described in
    https://tools.ietf.org/id/draft-dempsky-dnscurve-01.html#rfc.section.3

    """
    alph = dict(zip(range(32), "0123456789bcdfghjklmnpqrstuvwxyz"))
    return "".join(
        alph[(int.from_bytes(x, "little") >> i) & 0x1F]
        for i in range(0, len(x) * 8, 5)
    )


class Base32DecodeError(ValueError):
    pass


def base32_decode(x: str) -> bytes:
    """Inverse of base32_encode"""
    alph = dict(zip("0123456789bcdfghjklmnpqrstuvwxyz", range(32)))
    x = str(x).lower()

    if not all(c in alph.keys() for c in x):
        raise Base32DecodeError()

    return sum(alph[x[i]] << (5 * i) for i in range(len(x))).to_bytes(
        (5 * len(x) // 8), "little"
    )


def display_version() -> None:
    try:
        VERSION = importlib.metadata.version("pqconnect")
        print(f"PQConnect version {VERSION}")
    except Exception:
        logger.error("Error: Coult not determine version number")
