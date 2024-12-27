import selectors
import sys
from socket import AF_INET, SOCK_DGRAM, socket
from threading import Event, Thread
from time import monotonic, sleep
from typing import Tuple

from pqconnect.keys import PKTree
from pqconnect.pacing.pacing import PacingConnection, PacingPacket
from pqconnect.request import StaticKeyRequest, StaticKeyResponse

"""
Client starts sending requests in breadth-first order.
There is a thread sending packets and a thread receiving packets.
When a packet is sent, a semaphore must first be acquired
When a response is received, if the packet verifies, two requests are removed from
"""

THRESHOLD = 0.0001

HDRLEN = 28


def _queue_init(tree: PKTree) -> dict:
    """Generate a pacing packet to track each request packet sent to the keyserver"""
    pacing_packets = {}
    tree_struct = tree.get_structure()
    for depth in tree_struct.keys():
        for pos in range(tree_struct[depth]):
            req = StaticKeyRequest(depth=depth, pos=pos).payload
            pacing_pkt = PacingPacket(len(req) + HDRLEN)
            pacing_packets[(depth, pos)] = pacing_pkt

    return pacing_packets


def _send_level_from_queue(
    level: int,
    sock: socket,
    tree: PKTree,
    pc: PacingConnection,
    pacing_packets: dict,
) -> None:

    selector = selectors.DefaultSelector()
    selector.register(sock, selectors.EVENT_READ)

    indices = []
    for a, b in pacing_packets.keys():
        if a == level:
            indices.append((a, b))

    if level == 1:
        indices.insert(0, (0, 0))

    pkts = [pacing_packets[a, b] for a, b in indices]

    while indices:
        pc.now_update()

        p, idx, min_whenrto = min_rto(pc, indices, pacing_packets)

        whendecongested = float(pc.whendecongested(p.len))

        if whendecongested < THRESHOLD:
            if p.acknowledged:
                indices.remove(idx)
                continue

            if min_whenrto < THRESHOLD:
                a, b = idx
                req = StaticKeyRequest(a, b).payload
                sock.send(req)
                pc.transmitted(p)

        else:
            min_whenrto = whendecongested

        evts = selector.select(timeout=max(0, min_whenrto))
        if evts:
            _recv(sock, tree, pc, pacing_packets)

        status(pkts, level)


def min_rto(
    pc: PacingConnection, indices: list, pacing_packets: dict
) -> Tuple[PacingPacket, Tuple[int, int], float]:
    pc.now_update()
    pkts = [(i, pacing_packets[i]) for i in indices]
    i, p = min(pkts, key=lambda p: pc.whenrto(p[1]))
    return p, i, pc.whenrto(p)


#    while count:
#        count = tree_struct[level]
#        for j in range(tree_struct[level]):
#            pacing_packet = pacing_packets[level, j]
#            if pacing_packet.acknowledged:
#                count -= 1
#                continue
#            else:
#                req = StaticKeyRequest(level, j).payload
#                pc.now_update()
#                when = pc.whenrto(pacing_packet)
#                if when > THRESHOLD:
#                    continue
#
#                when = float(pc.whendecongested(len(req) + HDRLEN))
#                if when > THRESHOLD:
#                    evts = selector.select(timeout=when)
#                    if evts:
#                        _recv(sock, tree, pc, pacing_packets)
#                    if pacing_packet.acknowledged:
#                        continue


def status(pkts: list, level: int) -> None:
    total = len(pkts)
    acked = len([p for p in pkts if p.acknowledged])


def _send_from_queue(
    sock: socket,
    tree: PKTree,
    pc: PacingConnection,
    pacing_packets: dict,
) -> None:
    _send_level_from_queue(1, sock, tree, pc, pacing_packets)
    _send_level_from_queue(2, sock, tree, pc, pacing_packets)
    _send_level_from_queue(3, sock, tree, pc, pacing_packets)


def _recv(
    sock: socket,
    tree: PKTree,
    pc: PacingConnection,
    pacing_packets: dict,
) -> None:
    """Receive as many packets as are currently available and break once the
    receive buffer is empty

    Socket must be non-blocking

    """
    while True:
        try:
            data, _ = sock.recvfrom(4096)
            response = StaticKeyResponse(payload=data)
            depth = response.depth
            pos = response.pos
            keydata = response.keydata
            if not tree.insert_node(depth, pos, keydata):
                raise ValueError
            pacing_packet = pacing_packets[(depth, pos)]
            pc.now_update()
            pc.acknowledged(pacing_packet)

        except BlockingIOError:
            break

        except ValueError:
            continue


def request_static_keys(tree: PKTree, ip: str, port: int) -> None:
    """Requests static keys from the given ip and port and stores the received
    packets in the given PKTree object"""

    start = monotonic()
    pc = PacingConnection()

    s = socket(AF_INET, SOCK_DGRAM)
    s.connect((ip, port))
    s.setblocking(False)

    pacing_packets = _queue_init(tree)
    _send_from_queue(s, tree, pc, pacing_packets)
    s.close()

    end = monotonic()
    print(f"Duration: {end - start}")
