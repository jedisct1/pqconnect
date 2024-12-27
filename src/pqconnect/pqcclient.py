from multiprocessing.connection import Connection
from multiprocessing.synchronize import Event
from socket import AF_INET, SO_RCVBUF, SOCK_DGRAM, SOL_SOCKET, socket, timeout
from threading import Thread
from time import time
from typing import Dict, List, Optional, Tuple

from dns import resolver
from dns.rdtypes.ANY.TXT import TXT
from py25519 import dh, dh_keypair
from scapy.all import DNSRR, IP, UDP, dnstypes
from SecureString import clearmem

from pqconnect.common.constants import (
    A_RECORD,
    INITIATION_MSG,
    NUM_PREKEYS,
    SEG_LEN,
)
from pqconnect.common.crypto import NLEN, ekem, h, secret_box, skem
from pqconnect.common.crypto import stream_kdf as kdf
from pqconnect.common.util import base32_decode, base32_encode
from pqconnect.dns_parse import parse_pq1_record
from pqconnect.keys import PKTree
from pqconnect.log import logger
from pqconnect.pacing.pacing import PacingConnection, PacingPacket
from pqconnect.peer import Peer
from pqconnect.request import (
    EphemeralKeyRequest,
    EphemeralKeyResponse,
    KeyResponseHandler,
    StaticKeyRequest,
    StaticKeyResponse,
)
from pqconnect.request_static_key import request_static_keys
from pqconnect.tundevice import TunDevice
from pqconnect.tunnel import TunnelSession

MAX_FAILS = 10  # TODO add to constants file
TIMEOUT_SECONDS = 2  # TODO add to constants file


class PQCClient:
    def __init__(
        self,
        port: int,
        tun_conn: Connection,
        dns_conn: Connection,
        end_cond: Event,
        dev_name: str = "pqc0",
        host_ip: Optional[str] = None,
    ) -> None:
        self._device = TunDevice(
            port, tun_conn=tun_conn, dev_name=dev_name, host_ip=host_ip
        )

        self._dns_conn = dns_conn

        # {pkh: bytes {"ts": int, "mceliece": list, "x25519": bytes}}
        self._prekeys: dict = dict()

        self._end_cond = end_cond

        self._tun_thread = Thread(target=self._device.start)

    def generate_prekeys(
        self,
        pkh: bytes,
        mceliece_pk: bytes,
        x25519_pk: bytes,
        timestamp: Optional[int] = None,
    ) -> bool:
        """generates a cache of McEliece ciphertexts to be used in future
        handshakes with the peer

        Returns:
        False if we already have a non-empty cache for the peer
        True if new keys were generated

        """
        if not timestamp:
            now = int(time())

        else:
            now = timestamp

        # type checks
        if not (
            isinstance(pkh, bytes)
            and isinstance(mceliece_pk, bytes)
            and isinstance(x25519_pk, bytes)
        ):
            raise TypeError

        # This shouldn't be called when there already pre-computed keys, but
        # check anyway
        if pkh in self._prekeys and len(self._prekeys[pkh]["mceliece"]) > 0:
            return False

        self._prekeys[pkh] = {}
        self._prekeys[pkh]["ts"] = now
        self._prekeys[pkh]["x25519"] = x25519_pk
        self._prekeys[pkh]["mceliece"] = []

        for _ in range(NUM_PREKEYS):
            self._prekeys[pkh]["mceliece"].append(skem.enc(mceliece_pk))

        return True

    def _get_pk_hash(self, p: IP) -> tuple:
        """Parse public key hash from DNS response and return the raw 32-byte
        hash

        """
        if DNSRR in p:  # early reject if not a DNS response

            # iterate through answers
            for i in range(p.ancount):
                if DNSRR in p.an[i]:
                    if p.an[i][DNSRR].type == A_RECORD:
                        try:
                            name = p.an[i][DNSRR].rrname.decode("utf-8")
                            parsed_vals = parse_pq1_record(name)
                            if len(parsed_vals) > 0:
                                return parsed_vals
                        except Exception:
                            logger.exception(
                                "Could not decode public key hash: "
                                f"\x1b[33;20m{name.hex()}\x1b[0m"
                            )
                            continue
        return ()

    def _get_addrs(self, p: IP) -> list[str]:
        """Collect all IPv4 addresses from DNS answer records"""
        addrs = []
        if DNSRR in p:
            ancount = p.ancount
            if (
                ancount > 25
            ):  # https://stackoverflow.com/questions/6794926/how-many-a-records-can-fit-in-a-single-dns-response
                raise Exception(
                    "Suspicious packet. Too many response records."
                )
            for i in range(ancount):
                if DNSRR in p.an[i] and p.an[i][DNSRR].type == A_RECORD:
                    addrs.append(p.an[i][DNSRR].rdata)

        return addrs

    @staticmethod
    def _get_domain_name(p: IP) -> str:
        """Takes a scapy packet object and returns the rdata in the CNAME
        record

        """
        if DNSRR not in p:
            raise ValueError("packet has no response record")

        for i in range(p.ancount):
            if DNSRR in p.an[i] and dnstypes[p.an[i][DNSRR].type] == "A":
                return p.an[i][DNSRR].rrname.decode()

        return ""

    def _dns_handle(self, pkt: bytes) -> Tuple[bytes, Optional[Peer]]:
        """Checks incoming DNS packets from the netfilterqueue proxy for
        PQConnect PK hashes. If a hash is found, then the peer with this public
        key is returned if known, or a new peer is created and it is assigned a
        new internal IP.

        """

        p = IP(pkt)

        if DNSRR not in p:
            return (pkt, None)

        # Ignore TXT requests, as these are handled by the handshake thread directly
        for i in range(p.ancount):
            if DNSRR in p.an[i] and dnstypes[p.an[i][DNSRR].type] == "TXT":
                return (pkt, None)

        dns_vals: tuple = self._get_pk_hash(p)
        pqcport = None
        keyport = None

        if len(dns_vals) == 1:
            (pkhash,) = dns_vals

        elif len(dns_vals) == 3:
            (pkhash, pqcport, keyport) = dns_vals

        else:
            return (pkt, None)

        # Internal IP will either be created or retrieved from existing peer
        int_ip = None

        # Check if peer exists
        try:
            peer = self._device.get_peer_by_pkh(pkhash)
        except Exception:
            peer = None

        # Get the external IP
        try:
            ext_addrs = self._get_addrs(p)

            if len(ext_addrs) < 1:
                logger.warning(
                    "DNS response contains public key hash"
                    f" \x1b[33;20m{pkhash!r}\x1b[0m but no A record."
                )
                return pkt, None

            # TODO if there are multiple IPs we could try to ping them all and
            # connect to whichever responds first, i.e. fastest. Also good to
            # handle situations where there are both A and AAAA records

            if len(ext_addrs) > 1:
                logger.log(9, "Multiple A records found. Using the first one.")

            # Use first IP address
            ext_ip = ext_addrs[0]

            # If the client is running a stub resolver or local dns cache like
            # systemd-resolved or dnsmasq then we may see the same DNS response
            # twice. One coming from the network to the stub resolver, then the
            # same response arriving from the stub resolver to the application
            # that requested name resolution. PQConnect connections should not
            # be initiated from a DNS response that has already had its records
            # translated to an internal IP.
            if self._device.is_internal_ip_address(ext_ip):
                return (pkt, None)

        except Exception:
            return (pkt, None)

        if not peer:
            # Create one

            int_ip = (
                self._device.get_next_ip()
            )  # TODO likely ToCToU issue!. self.device.next_ip should be
            # incremented already.
            cname: str = self._get_domain_name(p)
            peer = Peer(ext_ip, int_ip, pkh=pkhash, cname=cname)

        # peer exists now, get its internal IP
        if not int_ip:
            int_ip = peer.get_internal_ip()

        # if we know the peer's keyport and pqcport, assign/update them
        if pqcport:
            peer.set_pqcport(pqcport)

        if keyport:
            peer.set_keyport(keyport)

        # replace all DNS answer records with internal ip
        for i in range(p.ancount):
            if DNSRR in p.an[i] and p.an[i][DNSRR].type == A_RECORD:
                p.an[i][DNSRR].rdata = int_ip
                p.an[i][DNSRR].ttl = 0

        # recompute checksums
        del p[IP].len
        del p[IP].chksum
        del p[UDP].len
        del p[UDP].chksum

        p.clear_cache()

        return bytes(p), peer

    def _has_prekeys(self, peer: Peer) -> bool:
        """Returns True iff peer has known static x25519 pk and a non-zero
        number of mceliece ciphertexts

        """
        try:
            pkh = peer.get_pkh()
            return (
                pkh in self._prekeys
                and len(self._prekeys[pkh]["mceliece"]) > 0
            )
        except Exception as e:
            logger.exception(e)
            return False

    def connect(self, peer: Peer) -> bool:
        """
        Connect to the given peer.

        If there is an active connection with the peer, return True.

        Dispatch a connection handler to create a new connection. If connection
        is successful (i.e. if we sent a handshake message), then return True,
        otherwise False (most likely because public keys couldn't be
        obtained/verified)

        """
        if peer.is_alive():
            logger.log(
                9, f"DNS reply for existing peer: {peer.get_internal_ip()}"
            )
            return True

        # Attempt a new connection
        pkh = peer.get_pkh()
        logger.info(
            f"Connecting to peer at {peer.get_external_ip()} "
            f"with pk hash {base32_encode(pkh)}"
        )

        # Send handshake using a pre-computed ciphertext if available
        if self._has_prekeys(peer):
            mceliece_ct = self._prekeys[pkh]["mceliece"].pop()
            x25519_pk = self._prekeys[pkh]["x25519"]

        else:
            mceliece_ct, x25519_pk = [b"", b""], b""

        ctx = PQCClientConnectionHandler(
            peer,
            self._device,
            self,
            mceliece_ct=mceliece_ct,
            s_x25519_r=x25519_pk,
        )

        # start handshake thread and return
        ctx.start()
        return True

    def start(self) -> None:
        """Starts two listeners as unprivileged user. One to handle packets
        forwarded by the TUN device, another to handle packets forwaded by the
        DNS proxy.

        The modified DNS responses are sent back to the requesting process
        after a connection has been initiated, so that subsequent DNS responses
        for this query give the same internal IP.

        """
        logger.info(f"Listening on port {self._device.get_pqcport()}")

        self._tun_thread.start()

        try:
            # Monitor incoming DNS packets from proxy.
            while not self._end_cond.is_set():
                if self._dns_conn.poll(0.1):  # timeout so we loop back
                    pkt = self._dns_conn.recv_bytes()
                    pkt, peer = self._dns_handle(pkt)
                    self._dns_conn.send_bytes(pkt)
                    if peer:
                        # Try to connect to peer. Add peer if successful TODO this
                        # should happen asynchronously so that connection issues do
                        # not interfere with future DNS request handles
                        if not self.connect(peer):
                            logger.error("Could not connect to peer")

        # TODO
        except Exception:
            pass

    def stop(self) -> None:
        self._end_cond.set()
        self._device.close()
        if self._tun_thread.is_alive():
            self._tun_thread.join()


class PQCClientConnectionHandler(Thread):
    """This class handles a new connection, obtaining public keys and
    performing a 0RTT handshake.

    """

    def __init__(
        self,
        peer: Peer,
        device: TunDevice,
        client: PQCClient,
        mceliece_ct: tuple[bytes, bytes] = (b"", b""),
        s_x25519_r: bytes = b"",
    ):
        super().__init__()
        self._transport = socket(AF_INET, SOCK_DGRAM)
        self._transport.settimeout(TIMEOUT_SECONDS)
        self._peer = peer

        self._device = device
        self._client = client

        self._pkh: bytes = peer.get_pkh()
        if not self._pkh:
            raise ValueError("Peer must have a public key hash")
        self._mceliece_ct: tuple[bytes, bytes] = mceliece_ct
        self._s_x25519_r: bytes = s_x25519_r
        self._s_mceliece_r: bytes = b""
        self._e_sntrup_r: bytes = b""
        self._e_x25519_r: bytes = b""
        self._e_x25519_i: bytes = b""
        self._e_x25519sk_i: bytes = b""
        self._pktree: PKTree = PKTree()

        self._pktree.insert_node(0, 0, self._pkh)

    def _resolve_keyserver_address(self) -> None:
        """Makes a DNS TXT query to get the keyserver ip and port values"""

        if not self._peer.get_cname():
            raise Exception("Missing server domain name")

        query_name = "ks." + self._peer.get_cname()

        answer: resolver.Answer = resolver.resolve(query_name, "TXT")

        try:
            if not answer.rrset:
                raise Exception("Text record does not exist")

            response_data: TXT = answer.rrset.pop()

            # response_data.to_text() should look like '"ip=1.2.3.4;p=12345"'

            ip, port = [
                r.split("=")[1].strip()
                for r in response_data.to_text().replace('"', "").split(";")
            ]

            self._peer.set_keyport(int(port))

        except Exception:
            raise ValueError(f"Keyserver DNS record is misconfigured")

    def _resolve_pqc_port(self) -> None:
        """Makes a DNS TXT query to get pqc port. Defaults to PQCPORT if not
        found.

        """

        if not self._peer.get_cname():
            raise Exception("Missing server domain name")

        port = None

        try:
            answer: resolver.Answer = resolver.resolve(
                self._peer.get_cname(), "TXT"
            )

            if not answer.rrset:
                raise Exception

            for resp in answer.rrset:

                # rr.to_text() should look like '"p=54321"'
                # remove any quotation marks and split into key, value
                # ignore any responses

                keyval = resp.to_text().replace('"', "").split("=")
                if len(keyval) != 2 or keyval[0].strip() != "p":
                    continue

                port = int(keyval[1])
                self._peer.set_pqcport(port)
                break

            if not port:
                raise Exception("port number not found in RR set")

        except (resolver.NXDOMAIN, Exception) as e:
            raise ValueError(f"PQConnect port TXT record does not exist: {e}")

    def _send_static_key_request(self, depth: int, pos: int) -> bool:
        """Send static key request to peer"""
        try:
            req = StaticKeyRequest(depth=depth, pos=pos)
            self._transport.sendto(
                req.payload,
                (self._peer.get_external_ip(), self._peer.get_keyport()),
            )
            return True
        except Exception as e:
            logger.exception(e)
            return False

    def _send_ephemeral_key_request(self) -> bool:
        """Send ephemeral key request to peer"""
        try:
            req = EphemeralKeyRequest().payload
            self._transport.sendto(
                req, (self._peer.get_external_ip(), self._peer.get_keyport())
            )
            return True
        except Exception as e:
            logger.exception(e)
            return False

    def _request_static_keys_paced(self) -> bool:
        """Uses Pacing Connection to request static keys while avoiding congestion"""

        ip = self._peer.get_external_ip()
        port = self._peer.get_keyport()

        if not ip or not port:
            return False

        logger.debug(
            f"Requesting static keys from {(self._peer.get_external_ip(), self._peer.get_keyport())}"
        )

        request_static_keys(self._pktree, ip, port)

        if not self._pktree.is_complete():
            return False

        self._s_mceliece_r = self._pktree.get_pqpk()
        self._s_x25519_r = self._pktree.get_npqpk()

        return True

    def _request_ephemeral_keys(self) -> bool:
        """Requests the current ephemeral keys from the server. Returns True if
        received

        """
        for _ in range(MAX_FAILS):
            logger.debug(
                f"Requesting ephemeral keys for peer at {self._peer.get_external_ip()}"
            )
            self._send_ephemeral_key_request()

            # There may be extra static key packets still arriving, so we just
            # receive packets until we have an ephemeral key or the socket
            # times out
            resp = None
            while True:
                try:
                    data, addr = self._transport.recvfrom(4096)
                    resp = KeyResponseHandler(data).response()
                    if not isinstance(resp, EphemeralKeyResponse):
                        continue
                    break
                except (TimeoutError, timeout):
                    logger.exception(
                        "Client connection handler socket timed out"
                    )
                    break

            try:
                if resp and isinstance(resp, EphemeralKeyResponse):
                    self._e_sntrup_r = resp.pqpk
                    self._e_x25519_r = resp.npqpk
                    return True
                else:
                    continue

            except Exception as e:
                continue

        return False

    def initiate_handshake_0rtt(
        self,
    ) -> tuple[bytes, bytes, bytes, bytes, bytes, TunnelSession]:
        #### k0
        # Encapsulate k0 against responder's long term McEliece pk
        # and mix k0 into cipherstate
        c0, self.cipher_state = self._mceliece_ct

        if not (c0 and self.cipher_state):
            raise Exception("No pre-keys found for this peer")

        # Store c0 in handshake_state
        self.handshake_state = c0

        # Generate ephemeral ECDH keys
        self._e_x25519_i, self._e_x25519sk_i = dh_keypair()

        # box epkIx25519
        c1, tag1 = secret_box(
            self.cipher_state,
            b"\x00" * NLEN,
            self._e_x25519_i,
            self.handshake_state,
        )

        self.handshake_state = h(self.handshake_state + c1 + tag1)

        #### k1
        k1 = dh(self._s_x25519_r, self._e_x25519sk_i)
        (self.cipher_state,) = kdf(
            1,
            self.cipher_state,
            k1,
        )

        clearmem(k1)

        #### k2
        k2 = dh(self._e_x25519_r, self._e_x25519sk_i)
        (self.cipher_state,) = kdf(
            1,
            self.cipher_state,
            k2,
        )

        clearmem(k2)

        #### k3
        c2, k3 = ekem.enc(self._e_sntrup_r)

        c3, tag3 = secret_box(
            self.cipher_state, b"\x00" * NLEN, c2, self.handshake_state
        )

        (self.cipher_state,) = kdf(1, self.cipher_state, k3)

        clearmem(k3)

        self.handshake_state = h(self.handshake_state + c3 + tag3)

        #### tid and final keys
        tid, ti, tr = kdf(3, self.cipher_state, self.handshake_state)

        return c0, c1, tag1, c3, tag3, TunnelSession(tid, ti, tr)

    def run(self) -> None:

        try:
            # Resolve server port
            if not self._peer.get_pqcport():
                self._resolve_pqc_port()

            # Resolve keyserver address
            if not self._peer.get_keyport():
                self._resolve_keyserver_address()

        except Exception as e:
            logger.warn(f"Error resolving DNS information")
            return

        # If we do not have a pre-computed mceliece ciphertext and the x25519
        # public key, we request the static keys and generate a mceliece
        # ciphertext
        c, k = self._mceliece_ct

        if not (c and k):
            try:
                if not self._request_static_keys_paced():
                    logger.debug(
                        f"Failed to obtain static keys for peer at {self._peer.get_external_ip()}"
                    )
                    return  # abort

                logger.debug(
                    f"Obtained static keys from {self._peer.get_external_ip()}"
                )
                self._mceliece_ct = skem.enc(self._s_mceliece_r)

            except Exception as e:
                logger.exception(
                    f"Failed to obtain static keys for peer at {self._peer.get_external_ip()}: {e}"
                )
                return  # abort

        # Request ephemeral keys from the server
        try:
            if not self._request_ephemeral_keys():
                logger.debug(
                    f"Failed to obtain ephemeral keys for peer at {self._peer.get_external_ip()}"
                )
                return  # abort

            logger.debug(
                f"Obtained ephemeral keys from {self._peer.get_external_ip()}"
            )

        except Exception as e:
            logger.exception(
                f"Failed to obtain ephemeral keys for peer at {self._peer.get_external_ip()}: {e}"
            )
            return  # abort

        # Compute and send the handshake message

        c0, c1, tag1, c3, tag3, session = self.initiate_handshake_0rtt()

        self._transport.sendto(
            INITIATION_MSG + b"".join([c0, c1, tag1, c3, tag3]),
            (self._peer.get_external_ip(), self._peer.get_pqcport()),
        )

        logger.debug(
            f"Sent handshake message to {self._peer.get_external_ip()}"
        )

        # Add peer
        self._peer.set_tunnel(session)
        self._device.add_peer(self._peer)

        # If we fetched the static keys at the start of this method, we should
        # precompute some mceliece ciphertexts and keys for the next time we
        # connect
        if self._s_mceliece_r and self._s_x25519_r:
            self._client.generate_prekeys(
                self._pkh, self._s_mceliece_r, self._s_x25519_r
            )

        self._transport.close()
