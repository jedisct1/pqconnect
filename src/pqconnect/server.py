from multiprocessing import Event, Pipe, Process
from os import _exit
from os.path import basename, dirname, join
from socket import inet_aton
from sys import exit as bye
from time import time

import click

from pqconnect.common.constants import (
    DAY_SECONDS,
    IP_SERVER,
    KEYPORT,
    MCELIECE_PK_PATH,
    MCELIECE_SK_PATH,
    PQCPORT,
    PRIVSEP_USER,
    SESSION_KEY_PATH,
    X25519_PK_PATH,
    X25519_SK_PATH,
)
from pqconnect.common.util import display_version, run_as_user
from pqconnect.iface import create_tun_interface, tun_listen
from pqconnect.keyserver import KeyServer
from pqconnect.keystore import EphemeralPrivateKeystore
from pqconnect.log import logger
from pqconnect.pqcserver import PQCServer


@run_as_user(PRIVSEP_USER)
def run_server(
    pqcs: PQCServer, keyserver: KeyServer, testing: bool = False
) -> None:
    """Runs the main client process as an unprivileged user"""
    # Create a new KeyServer object
    ev = Event()

    pqcs.start()
    keyserver.start()

    try:
        while not ev.is_set():
            # Generate ephemeral keys
            now = int(time())
            logger.info("Generating ephemeral keypairs")
            keystore = EphemeralPrivateKeystore(now)

            logger.info("Generating public ephemeral keystore")
            pkstore = keystore.get_public_keystore()

            # Add ephemeral private keys to the PQConnect server
            pqcs.set_keystore(keystore)

            # Add ephemeral public keys to the keyserver
            keyserver.set_keystore(pkstore)

            logger.info("Done generating ephemeral keypairs")
            ev.wait(DAY_SECONDS)

    except KeyboardInterrupt:
        logger.info("Shutting down PQConnect Server")
        ev.set()
        _exit(0)

    except Exception as e:
        logger.exception(e)
        ev.set()
        _exit(1)


@click.command()
@click.option("--version", is_flag=True, help="Display version")
@click.option(
    "-d",
    "--keydir",
    type=click.Path(
        file_okay=False,
        dir_okay=True,
        readable=True,
        resolve_path=True,
    ),
    default=dirname(MCELIECE_SK_PATH),
    help="Directory containing long-term keys",
)
@click.option(
    "-k",
    "--keyport",
    type=click.IntRange(0, 65535),
    default=KEYPORT,
    help="UDP listening port for key server",
)
@click.option(
    "-p",
    "--port",
    type=click.IntRange(0, 65535),
    default=PQCPORT,
    help="UDP listening port",
)
@click.option(
    "-a",
    "--addr",
    type=click.STRING,
    default=IP_SERVER,
    help="local IPv4 address",
)
@click.option(
    "-m",
    "--mask",
    type=click.IntRange(8, 24),
    default=16,
    help="netmask for private network",
)
@click.option(
    "-i",
    "--interface-name",
    type=click.STRING,
    default="pqcserv0",
    help="PQConnect network interface name",
)
@click.option("-v", "--verbose", is_flag=True, help="enable verbose logging")
@click.option(
    "-vv",
    "--very-verbose",
    is_flag=True,
    help="enable even more verbose logging",
)
@click.option(
    "-H",
    "--host-ip",
    type=click.STRING,
    help="IP address where decrypted traffic should arrive (required if PQConnect is running on a VM, for example)",
)
def main(
    version: bool,
    keydir: str,
    port: int,
    keyport: int,
    addr: str,
    mask: int,
    interface_name: str,
    verbose: bool,
    very_verbose: bool,
    host_ip: str,
) -> None:
    if version:
        display_version()
        bye()

    # Check addr for validity
    try:
        inet_aton(addr)
    except OSError:
        raise ValueError(f"Invalid IPv4 address: {addr}")

    # If host_ip was provided, check it is a valid ip address
    if host_ip:
        try:
            inet_aton(host_ip)
        except OSError:
            raise ValueError(f"Invalid IPv4 address: {host_ip}")

    if verbose:
        logger.setLevel(10)

    elif very_verbose:
        logger.setLevel(9)

    # Create TUN device
    try:
        tun_file = create_tun_interface(interface_name, addr, mask)
    except Exception:
        logger.exception("Could not create TUN device")
        bye(1)

    # Create pipe for interprocess communication
    root_conn, user_conn = Pipe()

    child_sig = Event()
    # Create subprocesses
    try:
        # Create PQCServer
        mceliece_path = join(keydir, basename(MCELIECE_SK_PATH))
        mceliece_pk_path = join(keydir, basename(MCELIECE_PK_PATH))
        x25519_path = join(keydir, basename(X25519_SK_PATH))
        x25519_pk_path = join(keydir, basename(X25519_PK_PATH))
        skey_path = join(keydir, basename(SESSION_KEY_PATH))

        pqcs = PQCServer(
            mceliece_path,
            x25519_path,
            skey_path,
            port,
            tun_conn=user_conn,
            dev_name=interface_name,
            host_ip=host_ip,
        )

        # Create KeyServer
        keyserver = KeyServer(mceliece_pk_path, x25519_pk_path, keyport)

        server_process = Process(target=run_server, args=(pqcs, keyserver))

        # Create tun_listen process
        tun_process = Process(
            target=tun_listen,
            args=(tun_file, root_conn, child_sig),
        )

    except Exception as e:
        logger.exception(e)
        bye(2)

    # Run
    try:
        tun_process.start()
        server_process.start()

        tun_process.join()
        server_process.join()
    except KeyboardInterrupt:
        logger.log(9, "KeyboardInterrupt caught in parent process")

    finally:
        tun_process.terminate()
        server_process.terminate()

        logger.log(9, "Closing Keyserver")
        keyserver.close()
        logger.log(9, "Keyserver closed")
        logger.log(9, "Closing PQCServer")
        pqcs.close()
        logger.log(9, "PQCServer closed")
        bye()


if __name__ == "__main__":
    main()
