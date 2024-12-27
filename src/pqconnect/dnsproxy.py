from multiprocessing import Event, Pipe
from multiprocessing.connection import Connection
from multiprocessing.synchronize import Event as ev
from select import select
from signal import SIGINT, SIGTERM, signal
from socket import AF_NETLINK, SOCK_RAW, fromfd
from sys import exit as bye
from types import FrameType
from typing import Optional

from netfilterqueue import NetfilterQueue, Packet

from .common.constants import MAGIC_NUMBER
from .common.util import NftablesError
from .log import logger
from .nft import NfqueueBuilder


class DNSNetfilterProxy:
    """Proxies DNS responses queued from netfilter.

    The constructor uses netfilter_queue to create a new firewall table and
    filter rule that queues DNS packets with source port 53 to the bound
    socket.

    The actual packet mangling is done by piping the packet to the client
    process running as an unprivileged user. The mangled packet is piped back
    and accepted by the queue, which hands it back to netfilter to return to
    the calling process.

    """

    def __init__(
        self,
        conn: Connection,
        netfilter_table: str = "pqconnect-filter",
        end_cond: Optional[ev] = None,
    ) -> None:
        self._conn = conn
        self._nfq = NetfilterQueue()

        # Add nftables table
        try:
            self._nfq_builder = NfqueueBuilder(netfilter_table)
            self._queue_no = self._nfq_builder.build()

        except Exception:
            logger.exception(f"Could not alter nftables")
            bye(1)

        # Dummy pipe for terminating the select poll
        self._end_cond: ev = end_cond if end_cond else Event()

        # Set signal handler to gracefully exit the run loop
        signal(SIGINT, self._signal_handle)
        signal(SIGTERM, self._signal_handle)

    def _signal_handle(self, signum: int, frame: Optional[FrameType]) -> None:
        """Sends an empty byte string to the connection that listens for a
        shutdown signal.

        """
        self._end_cond.set()

    def onResponse(self, msg: Packet) -> None:
        """Queued packets are sent here for handling and verdict
        (drop/accept). However, this process has to run as root in order to
        bind to the queue, and the incoming packets are hazmat.

        We render the verdict here but send packets via the pipe to the
        unprivileged client process for parsing and mangling.

        """
        pkt = msg.get_payload()

        # We can clearly skip any packets not containing the magic number
        # anywhere. Requires no parsing and probably saves a lot of time.
        # U+1f44D U+1f44D
        if MAGIC_NUMBER not in pkt:
            msg.accept()
            return

        # else the magic number is somewhere. Export it for mangling
        self._conn.send_bytes(pkt)
        new_msg = self._conn.recv_bytes()

        msg.set_payload(new_msg)
        msg.accept()

    def _run_queue(self) -> None:
        """Gets a raw netlink socket from the nfqueue file descriptor and
        listens for packets arriving in the netfilter queue until a SIGINT or
        SIGTERM is received.

        """
        s = fromfd(self._nfq.get_fd(), AF_NETLINK, SOCK_RAW)
        while not self._end_cond.is_set():
            r, _, _ = select([s], [], [], 0.1)
            if s in r:
                self._nfq.run_socket(s)

        s.close()

    def run(self) -> None:
        """Run the netfilterqueue"""
        # Bind the netfilter queue to our listener
        try:
            self._nfq.bind(self._queue_no, self.onResponse)

        except Exception:
            logger.exception("Could not bind queue")
            self.close()
            bye(2)

        # Everything is ready. Run the queue
        try:
            self._run_queue()

        except Exception:
            logger.exception("Error occurred while running netfilter queue")
            bye(3)

        finally:
            self.close()

    def close(self) -> None:
        """Teardown"""

        self._nfq.unbind()

        # Delete the nftables table
        try:
            self._nfq_builder.tear_down()
        except NftablesError:
            logger.exception("Error occured when deleting nftables table")


DNSProxy = DNSNetfilterProxy
