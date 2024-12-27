from sys import exit

import click
from dns import resolver
from dns.rdtypes.ANY.TXT import TXT
from dns.resolver import NXDOMAIN, NoNameservers

from .common.constants import DNS_EXAMPLE_HOST


def dns_query_server(hostname: str) -> tuple:
    """
    Query CNAME and server port for hostname
    """
    query_name: str = DNS_EXAMPLE_HOST
    try:
        answer_a: resolver.Answer = resolver.resolve(hostname, "A")

        if not answer_a.rrset:
            raise Exception("No response record")

        if not answer_a.canonical_name:
            raise Exception("No CNAME")

        cn: str = answer_a.canonical_name.to_text()

        for a in answer_a.rrset.to_rdataset():
            ip: str = a
        pk: str = cn.split("pq1")[1].split(".")[0]
    except Exception as e:
        print(f"Server DNS A record is misconfigured: {e}")
        exit(1)

    try:
        answer: resolver.Answer = resolver.resolve(cn, "TXT")
        if not answer.rrset:
            raise Exception("No response record")
        response_data: str = answer.rrset.pop().to_text()
        port = response_data.split('"')[1].split("=")[1]
    except Exception as e:
        print(f"Server DNS TXT record is misconfigured: {e}")
        exit(2)

    return (cn, pk, ip, port)


def dns_query_keyserver(cname: str) -> tuple:
    query_name: str = "ks." + cname
    try:
        answer: resolver.Answer = resolver.resolve(query_name, "TXT")
        if not answer.rrset:
            raise Exception("No response record")
        response_data: TXT = answer.rrset.pop()
        ip, port = [
            r.split("=")[1].strip()
            for r in response_data.to_text().replace('"', "").split(";")
        ]
    except Exception as e:
        print(f"Keyserver DNS TXT record is misconfigured: {e}")
        exit(3)

    return (ip, port)


@click.command()
@click.option(
    "-h",
    "--hostname",
    default=DNS_EXAMPLE_HOST,
    type=click.STRING,
    required=False,
)
def dns_query_main(hostname: str) -> tuple:
    """
    Query pqconnect related DNS records for a given hostname
    """
    cn, pk, ip, port = dns_query_server(hostname)
    ks_ip, ks_port = dns_query_keyserver(cn)

    print(
        f"Resolving: {hostname}\n"
        f"Found server: cname {cn}; ip {ip}; port {port}; with pk {pk}\n"
        f"Found Keyserver: ip {ks_ip}; port {ks_port}"
    )
    return (hostname, ip, port, pk)
