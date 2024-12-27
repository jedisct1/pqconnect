from unittest import TestCase

from pqconnect.common.constants import DNS_ENCODED_HASH_LEN
from pqconnect.dns_parse import parse_pq1_record


class TestDNSParse(TestCase):
    def test_parse_pq1_record_without_ports(self) -> None:

        self.assertEqual(
            parse_pq1_record(
                "pq1u1hy1ujsuk258krx3ku6wd9rp96kfxm64mgct3s3j26udp57dbu1.pqconnect.net"
            ),
            (
                b":<\x1f4\xc4:\x8a\x82\xe2\xed#j\xc3Y\xba5\x99\xd8\xfa4d\xba\x95\x07\x1eP\x18\xcdj9L\xe9",
            ),
            "Parsing without ports failed",
        )

    def test_parse_pq1_record_with_ports(self) -> None:
        self.assertEqual(
            parse_pq1_record(
                "pq1u1hy1ujsuk258krx3ku6wd9rp96kfxm64mgct3s3j26udp57dbu1zzz1zzz1.pqconnect.net"
            ),
            (
                b":<\x1f4\xc4:\x8a\x82\xe2\xed#j\xc3Y\xba5\x99\xd8\xfa4d\xba\x95\x07\x1eP\x18\xcdj9L\xe9",
                65535,
                65535,
            ),
            "Parsing with ports failed",
        )

    def test_parse_wrong_alphabet(self) -> None:
        name = "pq1aeio1ujsuk258krx3ku6wd9rp96kfxm64mgct3s3j26udp57dbu1.pqconnect.net"

        components = name.split(".")
        self.assertEqual(len(components[0][3:]), DNS_ENCODED_HASH_LEN)
        self.assertEqual(parse_pq1_record(name), ())
