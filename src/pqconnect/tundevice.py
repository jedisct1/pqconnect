import sys
from multiprocessing import Queue
from multiprocessing.connection import Connection
from selectors import EVENT_READ, DefaultSelector
from socket import AF_INET, SOCK_DGRAM, inet_aton, inet_ntop, socket
from threading import Event, Thread
from typing import TYPE_CHECKING, Dict, Optional

if TYPE_CHECKING:
    from .pqcserver import PQCServer

import ipaddress
from signal import SIGUSR1, signal
from time import monotonic
from types import FrameType
from typing import Optional, Union

from pyroute2 import IPRoute
from scapy.all import IP, TCP, UDP

from pqconnect.common.constants import (
    EPOCH_DURATION_SECONDS,
    HANDSHAKE_FAIL,
    INITIATION_MSG,
    MAX_CONNS,
    PQCPORT,
    TIDLEN,
    TUNNEL_MSG,
)
from pqconnect.cookie.cookie import Cookie, InvalidCookieMsgException
from pqconnect.cookie.cookiemanager import CookieManager, TimestampError
from pqconnect.log import logger
from pqconnect.peer import Peer, PeerState
from pqconnect.tunnel import TunnelSession


class TunDevice:
    """TunDevice encapsulates both a TUN/TAP device in TUN mode and maintains
    the list of active peer connections.

    We assign a dedicated IP to the device and perform NAT so that PQConnect
    peers will be routed to addresses in that subnet, just like in a VPN. This
    ensures that packets to and from PQConnect peers all appear to be coming
    from the device's address space and will be routed accordingly.

    Performing per-peer NAT also allows us to avoid modifying routing tables,
    which can be messy and easily get changed by the operating system.

    """

    def __init__(
        self,
        port: int,
        tun_conn: Connection,
        server: Optional["PQCServer"] = None,
        cookie_manager: Optional[CookieManager] = None,
        dev_name: str = "pqc0",
        subnet: str = "",  # For testing
        listening_ip: str = "0.0.0.0",
        host_ip: Optional[str] = None,
    ):
        # Reference to server object to create
        self._server = server
        self._cookie_manager = cookie_manager
        if self._cookie_manager:
            self._cookie_manager.start()

        # UDP socket to send and receive encapsulated packets

        self._tunnel_sock = socket(AF_INET, SOCK_DGRAM)
        self._tunnel_sock.bind((listening_ip, port))

        # Host IP
        self._host_ip = host_ip

        # Unix socket to communicate with parent process
        self._tun_conn = tun_conn

        # At various times we need to find peers from their attributes
        self._pkh2peer: Dict[bytes, Peer] = {}
        self._tid2peer: Dict[bytes, Peer] = {}
        self._int2peer: Dict[str, Peer] = {}
        self._ext2peer: Dict[str, Peer] = {}

        # Maintenance thread
        self._end_cond = Event()
        self._pruning_thread = Thread(target=self.remove_expired_peers)
        self._pruning_thread.start()

        # get ip and prefixlen from TUN device
        self._dev_name = dev_name
        self._my_ip, self._prefix_len = self._get_ip_from_iface(self._dev_name)

        if subnet:
            self._subnet4: bytes = inet_aton(subnet)

        else:
            subnet_int = int.from_bytes(inet_aton(self._my_ip), "big") & (
                0xFFFFFFFF << (32 - self._prefix_len)
            )
            self._subnet4 = int.to_bytes(subnet_int, 4, "big")

        # Create a FIFO packet queue for sending/receiving
        self._send_queue: Queue = Queue()
        self._recv_queue: Queue = Queue()
        self._handshake_queue: Queue = Queue()
        self._session_resume_queue: Queue = Queue()

        # initialize next_ip
        self._next_ip = 2

        # Register signal handler
        signal(SIGUSR1, self.print_from_signal)

    def print_from_signal(
        self, signum: int, frame: Union[int, Optional[FrameType]]
    ) -> None:
        """Prints active connections when SIGUSR1 is sent"""
        self.print_active_sessions()

    def print_active_sessions(self) -> None:
        """Prints the currently active sessions to stdout"""
        now = monotonic()
        pretty = (
            f"\x1b[33;93mActive Sessions: \x1b[4;91m{self._dev_name}"
            "\n\x1b[4;92mTunnelID\x1b[0m    "
            "\x1b[4;92mExternal IP\x1b[0m    "
            "\x1b[4;92mInternal IP\x1b[0m    "
            "\x1b[4;92mLast Active\x1b[0m"
        )
        for peer in self._int2peer.values():
            pretty += (
                "\n\x1b[33;93m{:<12}".format(peer.get_tid().hex()[-8:])
                + "{:<15}".format(peer.get_external_ip())
                + "{:<15}".format(peer.get_internal_ip())
            )
            last_ts = peer.last_used()
            if last_ts:
                pretty += "{:<.3f}s ago\x1b[0m\n".format(now - last_ts)

            else:
                pretty += "NEW\x1b[0m\n"

        print(pretty)

    def _get_ip_from_iface(self, iface_name: str) -> tuple[str, int]:
        """Returns the IP address and prefix length of @iface_name"""

        ip = IPRoute()
        dev_idx = ip.link_lookup(ifname=iface_name)[0]
        dump = ip.addr("dump", index=dev_idx)
        ip.close()
        return dump[0].get_attr("IFA_LOCAL"), dump[0]["prefixlen"]

    def _pton(self, addr: str) -> int:
        """Get the (32 - prefix_len) least-significant bits of an IPv4 addr,
        interpreted as a BE int

        """
        return int.from_bytes(inet_aton(addr), "big") & (
            0xFFFFFFFF >> self._prefix_len
        )

    def _make_local_ipv4(self, n: int) -> str:
        """Returns the local IPv4 address equal to the bitwise OR of the masked
        subnet and n as a BE uint.

        """
        if n >= (1 << (32 - self._prefix_len) or n < 0):
            raise ValueError(
                f"n must be in the interval [0, {1 << (32 - self._prefix_len)})"
            )
        loc = n.to_bytes(4, "big")
        ip = bytes((a | b for a, b in zip(self._subnet4, loc)))
        return inet_ntop(AF_INET, ip)

    def get_next_ip(self) -> str:
        """Returns the lowest available IP address in the subnet"""
        if self._next_ip >= MAX_CONNS:
            logger.debug("Too many connections. Pruning old ones.")
            self._prune_connection()

        return self._make_local_ipv4(self._next_ip)

    @staticmethod
    def _is_in_subnet(subnet_addr: str, prefix_len: int, addr: str) -> bool:
        """Returns whether addr is contained within subnet_addr/prefix_len"""

        ip = ipaddress.ip_address(addr)
        subnet = ipaddress.ip_network(
            f"{subnet_addr}/{prefix_len}", strict=False
        )
        return ip in subnet

    def is_internal_ip_address(self, addr: str) -> bool:
        """Returns true if address belongs to device subnet"""
        return self._is_in_subnet(self._my_ip, self._prefix_len, addr)

    def add_peer(self, peer: Peer) -> bool:
        """Add this peer to the collection. If successful, update the NAT
        counter to the next available internal IP and returns True

        """
        if peer.get_internal_ip() in self._int2peer.keys():
            logger.debug("Peer already exists. Ignoring.")
            return False

        if not (
            peer.get_tid() or peer.get_external_ip() or peer.get_internal_ip()
        ):
            logger.error("Peer is misconfigured")
            return False

        # Associate pkh to peer, if we're a client
        if not self._server:
            if not peer.get_pkh():
                logger.error("Server peer has no public key hash.")
                return False
            self._pkh2peer[peer.get_pkh()] = peer

        # Associate existing tunnel with peer, if created
        self._tid2peer[peer.get_tid()] = peer

        # Associate internal routing ip with peer
        self._int2peer[peer.get_internal_ip()] = peer

        self._ext2peer[peer.get_external_ip()] = peer

        # increment self.next_ip to next available free address
        while self._make_local_ipv4(self._next_ip) in self._int2peer.keys():
            self._next_ip += 1
            logger.debug(f"next routing IP: {self.get_next_ip()}")

        logger.info(
            "\x1b[33;20mNew Session Established: "
            "\x1b[33;92m External IP:\x1b[0m "
            f"{peer.get_external_ip()} "
            "\x1b[33;92m Internal IP:\x1b[0m "
            f"{peer.get_internal_ip()}"
        )

        self.print_active_sessions()
        return True

    def remove_expired_peers(self, test: bool = False) -> None:
        """Housekeeping routine to remove inactive peers. Every
        EPOCH_DURATION_SECONDS, peers are polled for liveness, and ones that
        are not alive are removed.

        """
        while True:
            self._end_cond.wait(timeout=EPOCH_DURATION_SECONDS)

            expired = []
            for peer in self._int2peer.values():
                if not peer.is_alive():
                    expired.append(peer)

            for peer in expired:
                self.remove_peer(peer)

            if self._end_cond.is_set():
                break

    def remove_peer(self, peer: Peer) -> None:
        """Removes `peer` from the instance. If the internal IP of `peer` is
        lower than `self.next_ip`, `self.next_ip` is reset to the peer's
        (masked) internal IP, interpreted as an unsigned int.

        """
        logger.info(f"Removing peer {peer.get_external_ip()}")

        if peer.get_tid() in self._tid2peer:
            self._tid2peer.pop(peer.get_tid())

        if peer.get_pkh() in self._pkh2peer:
            self._pkh2peer.pop(peer.get_pkh())

        if peer.get_internal_ip() in self._int2peer:
            self._int2peer.pop(peer.get_internal_ip())

            # set self.next_ip to be lowest available free ip
            if self._pton(peer.get_internal_ip()) < self._next_ip:
                self._next_ip = self._pton(peer.get_internal_ip())

        if peer.get_external_ip() in self._ext2peer:
            self._ext2peer.pop(peer.get_external_ip())

        peer.close()

    def get_peer_by_pkh(self, pkh: bytes) -> Peer:
        """Returns the peer indexed by `pkh`. Calling function should catch the
        potential KeyError

        """
        if not pkh or not isinstance(pkh, bytes):
            raise TypeError

        try:
            return self._pkh2peer[pkh]
        except KeyError as e:
            raise ValueError from e

    def get_pqcport(self) -> int:
        """Returns the port number of the network-facing socket"""
        return self._tunnel_sock.getsockname()[1]

    def _update_incoming_pk_addrs(
        self, decrypted_packet: bytes, src: str
    ) -> bytes:
        """Replaces the source IP on the inner packet with our peer's local
        routing IP.

        """
        pkt = IP(decrypted_packet)

        pkt[IP].src = src

        if self._host_ip:
            pkt[IP].dst = self._host_ip
        else:
            pkt[IP].dst = self._my_ip

        # We need to delete the existing packet header checksums or scapy will
        # not recompute it

        del pkt[IP].chksum
        if UDP in pkt:
            del pkt[UDP].chksum
        elif TCP in pkt:
            del pkt[TCP].chksum

        return pkt.build()

    def _generate_cookie(self, peer: Peer) -> Cookie:
        """Returns an cookie blob from the peer's current TunnelSession"""
        # TODO this is not very OOP-like, OOPs
        if not peer._tunnel or not self._cookie_manager:
            raise Exception

        key, nonce = self._cookie_manager.get_cookie_key()
        cookie = peer._tunnel.to_cookie(key, nonce)  # TODO violates OOP
        return cookie

    def _send_cookie(self, peer: Peer) -> None:
        """wraps generate_cookie and sends it over the network"""
        # Send a cookie to the indicated peer. Shouldn't be called directly,
        # but as part of a pruning action.
        try:
            cookie = self._generate_cookie(peer)

        except Exception as e:
            logger.exception(f"Could not generate a cookie for peer")
            return

        dst_ip = peer.get_external_ip()
        dst_port = peer.get_pqcport()

        self._tunnel_sock.sendto(
            peer.encrypt(cookie.bytes()), (dst_ip, dst_port)
        )

    def _prune_connection(self) -> None:
        """Send cookie to older connection if we're a server. Remove the
        connection.

        """

        old_peer = min(self._tid2peer.values(), key=lambda p: p.last_used())
        logger.debug(f"Peer: {old_peer.get_internal_ip()}")
        if self._cookie_manager:
            self._send_cookie(old_peer)

        self.remove_peer(old_peer)

    def _queue_incoming(self) -> None:
        """Sort incoming packet into the appropriate queue"""
        pkt, addr = self._tunnel_sock.recvfrom(4096)
        # First check if the server received an handshake or cookie message so
        # that we can create a new connection before handling the rest of the
        # packet (in the case of a cookie prepended to a regular message)

        if self._server:
            # Handle an initiation message
            if pkt[:2] == INITIATION_MSG:
                # 1) Complete handshake with packet in unprivileged thread
                # 2a) If tunnel is successfully created, add peer to tundevice
                # 2b) else send fail message
                self._handshake_queue.put((pkt, addr))
                logger.log(9, f"handshake message received from {addr[0]}")
                return

            # Handle cookie message
            elif self._cookie_manager and self._cookie_manager.is_cookie(pkt):
                self._session_resume_queue.put((pkt, addr))
                logger.log(9, f"cookie message received from {addr[0]}")
                return

        # Handle a message from an established connection.
        if pkt[:2] == TUNNEL_MSG:
            self._recv_queue.put((pkt, addr))
            return

        # If we receive a handshake fail message we should remove the peer
        # immediately
        elif pkt == HANDSHAKE_FAIL:
            if addr[0] in self._ext2peer.keys():
                peer = self._ext2peer[addr[0]]
                if peer.get_state() in (PeerState.ESTABLISHED, PeerState.NEW):
                    logger.error("Handshake failed")
                    peer.error()
                    self.remove_peer(peer)

    def _process_handshake_from_queue(self) -> None:
        """Gets a handshake message from the queue and processes it"""
        pkt, addr = self._handshake_queue.get()
        if self._server:
            self._server.complete_handshake(pkt, addr)

    def _process_cookie_from_queue(self) -> bool:
        """Gets a session restore message from queue and processes it. Returns
        success as a boolean

        """
        pkt, addr = self._session_resume_queue.get()

        if not self._cookie_manager:
            logger.error(
                9,
                "Cookie message received, but we can't issue cookies. ??",
            )
            return False

        try:
            tun: TunnelSession = self._cookie_manager.check_cookie(pkt)

        except InvalidCookieMsgException:
            logger.exception("Invalid cookie message")
            return False

        except TimestampError:
            logger.exception("Invalid cookie timestamp")
            return False

        except Exception:
            logger.exception("Could not processes cookie message")
            return False

        internal_ip = self.get_next_ip()
        peer = Peer(addr[0], internal_ip)
        peer.set_tunnel(tun)
        if addr[1] != PQCPORT:
            peer.set_pqcport(addr[1])
        self.add_peer(peer)

        return True

    def _receive_from_queue(self) -> None:
        """Gets a packet from the receive queue and decrypts it"""
        pkt, addr = self._recv_queue.get()

        tid = pkt[2 : 2 + TIDLEN]
        if tid in self._tid2peer:
            peer = self._tid2peer[tid]

            pkt = peer.decrypt(pkt)
            if pkt:
                logger.log(9, f"Message received from tunnel {tid.hex()}.")

                # Check if peer's external IP has changed
                ext_ip = addr[0]
                if ext_ip != peer.get_external_ip():
                    peer.set_external_ip(ext_ip)

                peer.set_pqcport(addr[1])

                # perform NAT so source IP comes from device subnet
                pkt = self._update_incoming_pk_addrs(
                    pkt, peer.get_internal_ip()
                )

                # Pass decrypted packet to tun device
                self._tun_conn.send_bytes(pkt)

    def _queue_send_packet(self) -> None:
        """Reads packet from the tunnel pipe and adds it to the send queue"""
        pkt = self._tun_conn.recv_bytes()
        self._send_queue.put(pkt)

    def _send_from_queue(self) -> None:
        """Gets a packet from the send queue and sends it if there is an active
        connection with the peer. Otherwise it re-inserts the packet into the
        queue or drops it, as appropriate.

        If the peer has no established tunnel yet, it reinserts for later
        processing. If the peer is expired, the packet is dropped.

        """
        pkt = self._send_queue.get()
        p = IP(pkt)

        if p[IP].dst in self._int2peer:
            peer = self._int2peer[p[IP].dst]

            state = peer.get_state()

            # If state is new, we're probably still waiting for the connection
            # to handshake to finish. Place back in the queue and return
            if state == PeerState.NEW:
                self._send_queue.put(pkt)
                return

            # If the peer has expired/closed/error, drop the packet, remove the
            # peer, and return
            elif (
                state in [PeerState.EXPIRED, PeerState.CLOSED, PeerState.ERROR]
                or not peer.is_alive()
            ):
                self.remove_peer(peer)
                return

            # Getting here means peer exists and connection is good.

            # Replace inner dst field, since it gets rewritten anyway
            p.dst = "0.0.0.0"

            # get outer packet address
            dst_ip = peer.get_external_ip()
            dst_port = peer.get_pqcport()

            self._tunnel_sock.sendto(
                peer.encrypt(bytes(p)), (dst_ip, dst_port)
            )
            logger.log(9, f"Message sent over tunnel {peer.get_tid().hex()}")

    def start(self) -> None:
        """Registers TUN device, external UDP socket, and message queues to the
        Selector for handling, then polls the selector until we exit.

        Selecting on private attributes (i.e. "_reader") is fragile, but there
        does not seem to be a better way to multiplex Queue reading without
        resorting to even uglier solutions. Also this has been a known issue
        for more than a decade now https://bugs.python.org/issue3831

        """
        sel = DefaultSelector()

        try:
            # __getattribute__
            send_reader = self._send_queue.__getattribute__("_reader")
            recv_reader = self._recv_queue.__getattribute__("_reader")
            handshake_reader = self._handshake_queue.__getattribute__(
                "_reader"
            )
            session_resume_reader = (
                self._session_resume_queue.__getattribute__("_reader")
            )

            # Register queues and IO
            socket_key = sel.register(self._tunnel_sock, EVENT_READ)
            tun_key = sel.register(self._tun_conn, EVENT_READ)
            send_key = sel.register(send_reader, EVENT_READ)
            recv_key = sel.register(recv_reader, EVENT_READ)
            handshake_key = sel.register(handshake_reader, EVENT_READ)
            session_resume_key = sel.register(
                session_resume_reader, EVENT_READ
            )

        except AttributeError:
            logger.exception("Message queues have no reader attribute")
            sys.exit(2)

        except Exception:
            logger.exception("Cannot register queues with selector")
            sys.exit(2)

        while not self._end_cond.is_set():
            for key, _ in sel.select(timeout=0.1):
                if key == socket_key:
                    self._queue_incoming()

                elif key == tun_key:
                    self._queue_send_packet()

                # We're the only thread the accessing the queues, so no ToCToU
                # issues should happen here
                elif key == send_key:
                    self._send_from_queue()

                elif key == recv_key:
                    self._receive_from_queue()

                elif key == handshake_key:
                    self._process_handshake_from_queue()

                elif key == session_resume_key:
                    self._process_cookie_from_queue()

    def close(self) -> None:
        """Terminates the pruning thread, closes all active connections and
        closes the connection to the TUN listener

        """
        for peer in self._int2peer.values():
            peer.close()

        logger.log(9, "Joining device pruning thread")
        self._end_cond.set()
        self._pruning_thread.join()
        logger.log(9, "device pruning thread joined")

        self._tunnel_sock.close()

        self._session_resume_queue.close()
        self._recv_queue.close()
        self._send_queue.close()
        self._handshake_queue.close()
        if self._cookie_manager:
            self._cookie_manager.stop()
