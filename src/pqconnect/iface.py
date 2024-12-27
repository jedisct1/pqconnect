from fcntl import ioctl
from io import FileIO
from ipaddress import IPv4Network, ip_network
from multiprocessing import Event
from multiprocessing.connection import Connection
from multiprocessing.synchronize import Event as EventClass
from os import read, write
from select import select
from socket import AF_INET, inet_pton
from struct import pack
from typing import List, Optional, Tuple

from pyroute2 import IPRoute

from pqconnect.log import logger


class AddressAlreadyInUseException(Exception):
    """Raised when a TUN device is assigned an address space that is in use by
    a different interface

    """

    def __init__(self, addr: str, prefix_len: int) -> None:
        super().__init__(
            f"Cannot create TUN device with address {addr}/{prefix_len}. "
            "Address is already in use."
        )


def get_existing_iface_addresses() -> List[IPv4Network]:
    """Returns a list of ip address spaces currently assigned to network
    interfaces on the host

    """
    ip = IPRoute()
    ip_dump = ip.addr("dump")
    ip.close()
    addr_list = []

    for record in ip_dump:
        record_prefix_len = record["prefixlen"]
        record_prefix = record.prefix
        record_addr = record.get_attr(f"{record_prefix}LOCAL")
        if record_addr:
            addr_list.append(
                IPv4Network((record_addr, record_prefix_len), strict=False)
            )

    return addr_list


def find_free_network(
    addr_list: List[IPv4Network], prefix_length: int
) -> IPv4Network:
    """Given a list of (IP, prefix-length) tuples and desired prefix-length,
    returns a non-overlapping RFC 1918 address space of the desired size

    """
    private_addresses = [
        IPv4Network("10.0.0.0/8", strict=False),
        IPv4Network("172.16.0.0/12", strict=False),
        IPv4Network("192.168.0.0/16", strict=False),
    ]

    existing_subnets = addr_list

    for network in private_addresses:
        if prefix_length < network.prefixlen:
            continue

        for subnet in network.subnets(new_prefix=prefix_length):
            if all(
                not subnet.overlaps(existing) for existing in existing_subnets
            ):
                return subnet

    raise ValueError()


def check_overlapping_address(
    address: str, prefix_len: int, iface_addrs: List[IPv4Network] = []
) -> bool:
    """Checks existing network interfaces and returns True if the
    address/prefix does not overlap with addresses assigned to other network
    devices.

    There is a potential ToCToU issue here, but address allocation is generally
    static and this is mainly to be used as a rough check.

    Optional keyword argument iface_addrs is a list of (address, prefix_len)
    tuples

    """
    # Take list from parameters
    if iface_addrs:
        addr_list = iface_addrs

    # Build list from existing interfaces
    else:
        addr_list = get_existing_iface_addresses()

    test_net = IPv4Network((address, prefix_len), strict=False)

    return all([not test_net.overlaps(addr) for addr in addr_list])


def create_tun_interface(name: str, addr: str, prefix_len: int) -> FileIO:
    """Creates a new TUN interface and assigns it a local IP address and
    routing mask

    """
    if not check_overlapping_address(addr, prefix_len):
        try:
            existing_addresses = get_existing_iface_addresses()
            free_subnet = find_free_network(existing_addresses, prefix_len)
            addr = str(free_subnet.network_address)
        except ValueError as e:
            raise AddressAlreadyInUseException(addr, prefix_len) from e

    tun = open(
        "/dev/net/tun", "r+b", buffering=0
    )  # ioctl constants from <linux/if_tun.h>
    TUNSETIFF = 0x400454CA
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000

    flags = IFF_TUN | IFF_NO_PI
    ifr = pack("16sH", name.encode("utf-8"), flags)
    ioctl(tun, TUNSETIFF, ifr)

    # Sanity check. Verify device exists
    ip = IPRoute()
    devs = ip.link_lookup(ifname=name)
    try:
        device_no = devs[0]

    except IndexError:
        raise Exception("Could not create TUN device. Device does not exist.")

    # Assign an address space to the device
    ip.addr("add", index=device_no, address=addr, prefixlen=prefix_len)

    # set the device status to up
    ip.link("set", index=device_no, state="up", mtu=1200)

    ip.close()
    return tun


def tun_listen(tun_file: FileIO, conn: Connection, evt: EventClass) -> None:
    """Relays messages between the TUN device and the client process. The
    calling process can terminate it by setting the condition variable @event

    """

    while True:
        if evt.is_set():
            break

        r, _, _ = select([conn, tun_file], [], [], 0.5)
        if conn in r:
            data = conn.recv_bytes()
            write(tun_file.fileno(), data)

        if tun_file in r:
            data = read(tun_file.fileno(), 4096)
            conn.send_bytes(data)
