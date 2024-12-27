import logging
from grp import getgrnam
from os import chmod, environ, remove, rmdir, stat, umask
from os.path import exists, isdir, isfile, join
from pathlib import Path
from pwd import getpwnam
from sys import exit as bye

import click

from pqconnect.common.constants import (
    CONFIG_PATH,
    DEFAULT_KEYPATH,
    KEYPORT,
    PQCPORT,
    PRIVSEP_USER,
)
from pqconnect.common.crypto import dh, randombytes, skem
from pqconnect.common.util import base32_encode
from pqconnect.keys import PKTree


def check_config_path(config_path: str, dns_only: bool) -> bool:
    """Checks that config directory exists, and if not, creates one at
    CONFIG_PATH, owned by root but visible to everyone.

    """
    if not isdir(config_path):

        if dns_only:
            return False

        ans = input(
            f"{config_path} does not exist. Would you like to create it? [y/N]"
        )

        if ans != "y":
            return False

        umask(0o022)
        Path(config_path).mkdir(parents=True)

    return True


def get_port_from_config(
    config_path: str, port_name: str, dns_only: bool
) -> int:
    port_file = join(config_path, port_name)

    if not isfile(port_file):
        if dns_only:
            raise FileNotFoundError()

        if port_name == "keyport":
            ans = input(
                f"Please enter the listening port of your keyserver (Default: {KEYPORT})"
            )

            if ans == "":
                ans = str(KEYPORT)

        elif port_name == "pqcport":
            ans = input(
                f"Please enter the listening port for the PQConnect server (Default: {PQCPORT})"
            )

            if ans == "":
                ans = str(PQCPORT)

        port = int(ans)
        if port not in range(1, 1 << 16):
            raise ValueError

        umask(0o022)
        with open(port_file, "w") as f:
            f.write(ans)

    with open(port_file, "r") as f:
        port = int(f.read().strip())
        port &= 65535
        return port


def save_keys(
    keypath: str,
    mceliece_pk: bytes,
    mceliece_sk: bytes,
    x25519_pk: bytes,
    x25519_sk: bytes,
    sk: bytes,
) -> bool:
    """Saves the given keys to disk"""

    pqconnect_uid = getpwnam(PRIVSEP_USER).pw_uid
    pqconnect_gid = getgrnam(PRIVSEP_USER).gr_gid

    files = {
        "mceliece_pk": mceliece_pk,
        "mceliece_sk": mceliece_sk,
        "x25519_pk": x25519_pk,
        "x25519_sk": x25519_sk,
        "session_key": sk,
    }

    try:
        umask(0o022)

        if not isdir(keypath):
            ans = input(
                f"{keypath} does not exist. Would you like to create it? [y/N]"
            )

            if ans != "y":
                return False

            else:
                Path(keypath).mkdir(parents=True)

        for filename in ["mceliece_pk", "x25519_pk"]:
            path = join(keypath, filename)

            if exists(path):
                ans = input(f"{path} exists. Overwrite? [y/N]: ")

                if ans != "y":
                    return False

            with open(path, "wb") as f:
                f.write(files[filename])
                f.close()

        umask(0o077)

        for filename in ["mceliece_sk", "x25519_sk", "session_key"]:
            path = join(keypath, filename)

            if exists(path):
                ans = input(f"{path} exists. Overwrite? [y/N]: ")

                if ans != "y":
                    return False

            with open(path, "wb") as f:
                f.write(files[filename])
                f.close()

    except Exception:
        return False

    return True


def log_key_info(keypath: str, pqcport: int, keyport: int) -> bool:
    """Writes public key hash and DNS information to log"""
    DNS_HOWTO = join(keypath, "DNS_Record_Update_HOWTO.txt")

    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        filename=DNS_HOWTO,
        filemode="w",
    )

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    logging.getLogger().addHandler(console)

    try:
        tree = PKTree.from_file(
            join(keypath, "mceliece_pk"),
            join(keypath, "x25519_pk"),
        )

        logging.info(
            "\nThe public key hash for your keys is: "
            f"{tree.get_base32_encoded_pubkey_hash()}\n"
        )
        full_name = (
            tree.get_base32_encoded_pubkey_hash()
            + base32_encode(bytes.fromhex(hex(65536 + pqcport)[-4:]))
            + base32_encode(bytes.fromhex(hex(65536 + keyport)[-4:]))
        )
        logging.info(
            "Please update your DNS A/AAAA records for all domains on this "
            "server as follows:\n\n"
            "Existing record:\n"
            "Type    Name        Value\n"
            "A/AAAA  SUBDOMAIN   IP Address\n\n"
            "New Records:\n"
            "Type    Name        Value\n"
            f"CNAME   SUBDOMAIN   pq1{full_name}"
            ".DOMAIN.TLD\n"
            f"A/AAAA  pq1{full_name}   IP Address\n"
        )
        logging.info(
            "IMPORTANT: If SUBDOMAIN has NS records, do not make this change.\n"
            "Instead set up another SUBDOMAIN for the server.\n"
        )

        print(f"\n\nView the file {DNS_HOWTO} for a copy of the above output.")

    except Exception:
        logging.exception("Could not load keys from disk")
        return False

    return True


def static_keygen(
    keypath: str, pqcport: int, keyport: int, dns_only: bool
) -> bool:
    """Generates static keys and writes each key to keypath/<KEY_FILE>"""
    # Generate keys
    if dns_only:
        return log_key_info(keypath, pqcport, keyport)

    try:
        # Generate McEliece keys
        print("Generating McEliece keypair")
        mceliece_pk, mceliece_sk = skem.keypair()

        # Generate ECC keys
        print("Generating X25519 keypair")
        x25519_pk, x25519_sk = dh.dh_keypair()

        # Generate and save Session key
        print("Generating symmetric session key")
        sk = randombytes(32)

        print("Keys generated successfully")

    except Exception:
        logging.exception("Could not generate keys")
        return False

    # Save to disk
    if not save_keys(
        keypath, mceliece_pk, mceliece_sk, x25519_pk, x25519_sk, sk
    ):
        logging.exception("Could not save keys to disk")
        return False

    return log_key_info(keypath, pqcport, keyport)


@click.command()
@click.option(
    "-c",
    "--config-dir",
    type=str,
    default=CONFIG_PATH,
    help="PQConnect server config directory",
)
@click.option(
    "-d",
    "--directory",
    type=str,
    default=DEFAULT_KEYPATH,
    help="directory where key files will be stored",
)
@click.option(
    "-D",
    "--dns-only",
    is_flag=True,
    default=False,
    help="print DNS records for existing configuration",
)
def main(directory: str, config_dir: str, dns_only: bool) -> None:
    """Generate and save long term keys"""
    # Log the DNS update information to a file

    keypath = directory

    if not check_config_path(config_dir, dns_only):
        print("Could not locate config directory")
        bye(1)
    try:
        pqcport = get_port_from_config(config_dir, "pqcport", dns_only)
        keyport = get_port_from_config(config_dir, "keyport", dns_only)

    except ValueError:
        print("Invalid port configuration")
        bye(2)

    if not static_keygen(keypath, pqcport, keyport, dns_only):
        print("Error occurred during key generation")
        bye(3)

    bye()


if __name__ == "__main__":
    main()
