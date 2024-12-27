from multiprocessing import Event, Pipe, Process, active_children
from multiprocessing.connection import Connection
from multiprocessing.synchronize import Event as Ev
from os import getpid, getuid, kill, remove
from os.path import exists
from pwd import getpwnam
from signal import SIG_IGN, SIGINT, SIGTERM, SIGUSR1, signal
from socket import inet_aton
from sys import exit as bye
from time import sleep
from types import FrameType
from typing import Dict, Optional

import click

from pqconnect.common.constants import (
    IP_CLIENT,
    PIDCLIENTPATH,
    PIDPATH,
    PQCPORT_CLIENT,
    PRIVSEP_USER,
)
from pqconnect.common.util import display_version, run_as_user
from pqconnect.dnsproxy import DNSNetfilterProxy
from pqconnect.iface import create_tun_interface, tun_listen
from pqconnect.log import logger
from pqconnect.pqcclient import PQCClient


def send_usr1_to_client(client_pid_path: str = PIDCLIENTPATH) -> None:
    """Opens pid file for client and sends a SIGUSR1 signal to that pid"""

    try:
        with open(client_pid_path, "r") as f:
            pid = int(f.read().strip())
            kill(pid, SIGUSR1)
    except FileNotFoundError:
        print("\x1b[33;93mError:\x1b[0m Is PQConnect running?")


@run_as_user(PRIVSEP_USER)
def run_client(
    port: int,
    tun_conn: Connection,
    dns_conn: Connection,
    event: Ev,
    dev_name: str,
    host_ip: Optional[str],
) -> None:
    """Runs the main client process as an unprivileged user"""

    try:
        # Initialize client (privsep)
        client = PQCClient(
            port, tun_conn, dns_conn, event, dev_name=dev_name, host_ip=host_ip
        )

    except Exception as e:
        logger.exception(f"Could not initialize client: {e}")
        bye(1)

    client.start()


@click.command()
@click.option("--version", is_flag=True, help="Display version")
@click.option(
    "-p",
    "--port",
    type=click.IntRange(0, 65535),
    default=PQCPORT_CLIENT,
    help="UDP listening port",
)
@click.option(
    "-a",
    "--addr",
    type=click.STRING,
    default=IP_CLIENT,
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
    default="pqccli0",
    help="PQConnect network interface name",
)
@click.option("-v", "--verbose", is_flag=True, help="enable verbose logging")
@click.option(
    "-vv",
    "--very-verbose",
    is_flag=True,
    help="enable even more verbose logging",
)
@click.option("--show", is_flag=True, help="show active PQConnect connections")
@click.option(
    "-H",
    "--host-ip",
    type=click.STRING,
    help="IP address where decrypted traffic should arrive (required if PQConnect is running on a VM, for example)",
)
def main(
    version: bool,
    port: int,
    addr: str,
    mask: int,
    interface_name: str,
    verbose: bool,
    very_verbose: bool,
    show: bool,
    host_ip: Optional[str],
) -> None:
    if version:
        display_version()
        bye()

    if show:
        send_usr1_to_client(PIDCLIENTPATH)
        bye()

    if getuid() != 0:
        logger.error("PQConnect must be run as root")
        bye(1)

    if exists(PIDPATH):
        try:
            with open(PIDPATH, "r") as f:
                pid = int(f.read().strip())
                kill(pid, 0)
                print("\x1b[33;93mError:\x1b[0m PQConnect is already running.")
                bye(1)
        except Exception:  # .pid file is stale. Delete and continue
            remove(PIDPATH)

    try:
        getpwnam(PRIVSEP_USER)
    except KeyError:
        logger.exception(
            f"User {PRIVSEP_USER} does not exist."
            " Please create it before starting PQConnect"
        )
        bye(1)

    try:
        inet_aton(addr)
    except OSError:
        logger.exception(f"Invalid IPv4 address: {addr}")
        bye(1)

    if verbose:
        logger.setLevel(10)

    elif very_verbose:
        logger.setLevel(9)

    # create TUN device
    try:
        tun_file = create_tun_interface(interface_name, addr, mask)

    except PermissionError:
        logger.exception("Operation not permitted")
        bye(1)

    except Exception as e:
        logger.exception(e)
        bye(1)

    logger.info("Starting PQConnect")

    child_sig = Event()
    children: Dict[Optional[int], str] = {}

    # socket to pass packets to/from tun device
    tun_conn0, tun_conn1 = Pipe()

    # Pipe to pass packets to/from DNS proxy
    dns_conn0, dns_conn1 = Pipe()

    try:
        # DNS proxy (root)
        dns_proxy = DNSNetfilterProxy(dns_conn0)

    except Exception as e:
        logger.exception(f"Could not initialize DNS Proxy: {e}")
        bye(1)

    # Client process (pqconnect)
    cli_proc = Process(
        target=run_client,
        args=(port, tun_conn1, dns_conn1, child_sig, interface_name, host_ip),
    )

    # TUN relay (root)
    tun_proc = Process(
        target=tun_listen,
        args=(tun_file, tun_conn0, child_sig),
    )

    # DNS proxy (root)
    dns_proc = Process(target=dns_proxy.run)

    def graceful_shutdown(signum: int, frame: Optional[FrameType]) -> None:
        """Gracefully shut down child processes"""
        child_sig.set()
        if signum == SIGINT:
            bye(0)

        if signum == SIGTERM:
            bye(SIGTERM)

    def set_signal_handlers() -> None:
        """Sets signal handlers for the main process

        SIGTERM and SIGINT should both trigger graceful shutdown

        SIGUSR1 should be ignored (terminates process by default), as we will
        use it in the client child process

        """
        # set Signal handlers
        signal(SIGTERM, graceful_shutdown)
        signal(SIGINT, graceful_shutdown)
        signal(SIGUSR1, SIG_IGN)

    set_signal_handlers()
    # Run
    try:
        logger.info("Starting DNS Proxy...")
        dns_proc.start()
        children[dns_proc.pid] = "DNS Proxy"

        logger.info("Starting TUN listener")
        tun_proc.start()
        children[tun_proc.pid] = "TUN Process"

        logger.info("Starting client")
        cli_proc.start()
        children[cli_proc.pid] = "Client Process"

        with open(PIDPATH, "w") as f:
            f.write(str(getpid()))

        with open(PIDCLIENTPATH, "w") as f:
            f.write(str(cli_proc.pid))

        dns_proc.join()
        tun_proc.join()
        cli_proc.join()

    finally:
        logger.info("Exiting...")
        dns_conn0.close()

        tun_file.close()
        tun_conn0.close()

        tun_conn1.close()
        dns_conn1.close()

        # Children should have stopped. Log any stragglers and then kill them.
        sleep(1)
        for p in active_children():
            if p.is_alive():
                logger.error(
                    f"{children[p.pid]} did not terminate. Killing..."
                )
                p.terminate()

        remove(PIDPATH)
        remove(PIDCLIENTPATH)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        bye(1)
