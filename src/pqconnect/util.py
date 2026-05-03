from pathlib import Path, PurePath
from sys import exit
from typing import List, Optional

import click
from dns import resolver
from dns.rdtypes.ANY.TXT import TXT
from dns.resolver import NXDOMAIN

from pqconnect.common.constants import CONFIG_PATH
from pqconnect.common.util import base32_encode
from pqconnect.dns_parse import parse_pq1_record


def dns_query_cryptoport(cname: str) -> int:
    """"""
    try:
        answer: resolver.Answer = resolver.resolve(cname, "TXT")
        if not answer.rrset:
            raise Exception(f"Could not resolve {cname}")
        response_data: str = answer.rrset.pop().to_text()
        cryptoport = response_data.split('"')[1].split("=")[1]
        return int(cryptoport)

    except Exception as e:
        raise Exception(f"Could not obtain cryptoport from DNS: {e}.")


def dns_query_keyserver(cname: str) -> tuple:
    try:
        query_name: str = "ks." + cname
        answer: resolver.Answer = resolver.resolve(query_name, "TXT")
        if not answer.rrset:
            raise Exception(f"Could not resolve {query_name}")
        response_data: TXT = answer.rrset.pop()
        ip, port = [
            r.split("=")[1].strip()
            for r in response_data.to_text().replace('"', "").split(";")
        ]
        return (ip, int(port))

    except Exception as e:
        raise Exception(f"Could not obtain keyport from DNS: {e}.")


def dns_query_server(hostname: str) -> tuple:
    """
    Query CNAME and server port for hostname
    """
    host = f"\x1b[33;93m{hostname}\x1b[0m"

    print(f"Checking DNS confirmation for {host}")

    try:
        answer_a: resolver.Answer = resolver.resolve(hostname, "A")

    except Exception as e:
        raise Exception(f"Unable to resolve {hostname}: {e}")

    if not answer_a.canonical_name:
        raise Exception(f"No CNAME found for {hostname}.")

    if not answer_a.rrset:
        raise Exception(f"No DNS response records found for {hostname}")

    cn: str = answer_a.canonical_name.to_text()
    for a in answer_a.rrset.to_rdataset():
        ip: str = a

    try:
        # This can raise a TypeError, or return 0, 1, or 3 values
        vals = parse_pq1_record(cn)
        if not vals:
            raise Exception

    except Exception:
        raise Exception(f"Could not parse PQConnect values from CNAME {cn}.")

    try:
        # CNAME contains public key hash and ports
        if len(vals) == 3:
            pk, cryptoport, keyport = vals

        # CNAME only contains public key hash, need to do additional queries for ports
        elif len(vals) == 1:
            (pk,) = vals

            cryptoport = dns_query_cryptoport(cn)
            _, keyport = dns_query_keyserver(cn)

    except Exception:
        raise

    return (cn, pk, ip, cryptoport, keyport)


def check_port_config_files(config_dir: Path, errs: list) -> tuple:
    """Try to read and return keyport and cryptoport values from the given
    CONFIG_DIR. along with any ERRS encountered.

    """
    keyport: Optional[int] = None
    cryptoport: Optional[int] = None
    # keyport
    try:
        with PurePath.joinpath(config_dir, "keyport").open() as f:
            keyport = int(f.readline().strip())

    except Exception as e:
        errs.append(e)

    # cryptoport
    try:
        with PurePath.joinpath(config_dir, "pqcport").open() as f:
            cryptoport = int(f.readline().strip())

    except Exception as e:
        errs.append(e)

    return (cryptoport, keyport, errs)


@click.command()
@click.argument("hostname")
@click.option(
    "-c",
    "--config-dir",
    type=click.Path(
        file_okay=False, exists=True, resolve_path=True, path_type=Path
    ),
    default=CONFIG_PATH,
    help="Configuration file directory",
)
@click.option(
    "-D",
    "--dns-only",
    is_flag=True,
    help="Only check DNS records (Ignore local configuration files)",
)
def main(hostname: str, config_dir: Path, dns_only: bool = False) -> None:
    errs: List[Exception] = []
    cn = pk = ip = cryptoport = keyport = None
    try:
        cn, pk, ip, cryptoport, keyport = dns_query_server(hostname)

        print(
            f"PQConnect DNS configuration found.\n"
            f"- \x1b[33;92mCNAME:\x1b[0m {cn}\n"
            f"- \x1b[33;92mPublic key hash:\x1b[0m\n"
            f"  - \x1b[33;93mbase32:\x1b[0m {base32_encode(pk)}\n"
            f"  - \x1b[33;93mhex:\x1b[0m {pk.hex()}\n"
            f"- \x1b[33;92mIP address:\x1b[0m {ip}\n"
            f"- \x1b[33;92mListening port:\x1b[0m {cryptoport}\n"
            f"- \x1b[33;92mKeyserver port:\x1b[0m {keyport}"
        )

    except Exception as e:
        errs.append(e)

    if not dns_only:
        cryptoport_config, keyport_config, errs = check_port_config_files(
            config_dir, errs
        )

        if (
            cryptoport_config
            and cryptoport
            and not int(cryptoport) == int(cryptoport_config)
        ):
            errs.append(
                Exception(
                    f"Cryptoport in DNS ({cryptoport}) does not match config file ({cryptoport_config}). "
                    "If this is your domain, please update your DNS."
                )
            )

        if (
            keyport_config
            and keyport
            and not int(keyport) == int(keyport_config)
        ):
            errs.append(
                Exception(
                    f"Keyport in DNS ({keyport}) does not match config file ({keyport_config}). "
                    "If this is your domain, please update your DNS."
                )
            )

    if errs:
        print("\n")
        print(f"{len(errs)} Error(s) found.")
        for err in errs:
            print(f"- \x1b[33;91mError:\x1b[0m {err}")
