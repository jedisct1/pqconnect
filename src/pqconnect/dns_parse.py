import sys

from pqconnect.common.constants import (
    DNS_ENCODED_HASH_LEN,
    DNS_ENCODED_PORT_LEN,
    SUPPORTED_MAJOR_VERSIONS,
)
from pqconnect.common.util import Base32DecodeError, base32_decode


def parse_pq1_record(name: str) -> tuple:
    """Parses a keyhash and (possibly) port numbers from a pqconnect advertisement in DNS"""

    if not isinstance(name, str):
        raise TypeError()

    names = name.split(".")

    # from left to right
    for component in names:

        # starts with pq1, pq2, etc.
        if (
            len(component) > 2
            and component[:2] == "pq"
            and component[2] in SUPPORTED_MAJOR_VERSIONS
        ):
            data = component[3:]

            try:

                if len(data) == DNS_ENCODED_HASH_LEN:
                    keyhash = base32_decode(data)
                    return (keyhash,)

                elif len(data) == (
                    DNS_ENCODED_HASH_LEN
                    + DNS_ENCODED_PORT_LEN
                    + DNS_ENCODED_PORT_LEN
                ):
                    idx = DNS_ENCODED_HASH_LEN

                    keyhash = base32_decode(data[:idx])

                    pqcport = int(
                        base32_decode(
                            data[idx : idx + DNS_ENCODED_PORT_LEN]
                        ).hex(),
                        16,
                    )

                    idx += DNS_ENCODED_PORT_LEN
                    keyport = int(
                        base32_decode(
                            data[idx : idx + DNS_ENCODED_PORT_LEN]
                        ).hex(),
                        16,
                    )

                    return (keyhash, pqcport, keyport)

            except Base32DecodeError:
                return ()

    return ()
