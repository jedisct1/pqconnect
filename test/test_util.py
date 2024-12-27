from unittest import TestCase

from pqconnect.common import util


class TestUtil(TestCase):
    def test_base32_encoding(self) -> None:
        """taken from
        https://datatracker.ietf.org/doc/html/draft-dempsky-dnscurve-01#section-3.1

        """
        vectors = [
            (b"\x64\x88", "4321"),
            (b"", ""),
            (b"\x88", "84"),
            (b"\x9f\x0b", "zw20"),
            (b"\x17\xa3\xd4", "rs89f"),
            (b"\x2a\xa9\x13\x7e", "b9b71z1"),
            (b"\x7e\x69\xa3\xef\xac", "ycu6urmp"),
            (b"\xe5\x3b\x60\xe8\x15\x62", "5zg06nr223"),
            (b"\x72\x3c\xef\x3a\x43\x2c\x8f", "l3hygxd8dt31"),
            (b"\x17\xf7\x35\x09\x41\xe4\xdc\x01", "rsxcm44847r30"),
        ]

        for a, b in vectors:
            self.assertEqual(util.base32_encode(a), b)

    def test_base32_decoding(self) -> None:
        """Tests that decoding also works"""
        vectors = [
            (b"\x64\x88", "4321"),
            (b"", ""),
            (b"\x88", "84"),
            (b"\x9f\x0b", "zw20"),
            (b"\x17\xa3\xd4", "rs89f"),
            (b"\x2a\xa9\x13\x7e", "b9b71z1"),
            (b"\x7e\x69\xa3\xef\xac", "ycu6urmp"),
            (b"\xe5\x3b\x60\xe8\x15\x62", "5zg06nr223"),
            (b"\x72\x3c\xef\x3a\x43\x2c\x8f", "l3hygxd8dt31"),
            (b"\x17\xf7\x35\x09\x41\xe4\xdc\x01", "rsxcm44847r30"),
        ]

        for a, b in vectors:
            self.assertEqual(util.base32_decode(b), a)
