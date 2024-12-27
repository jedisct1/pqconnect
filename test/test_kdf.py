from unittest import TestCase, main

from pqconnect.common.crypto import h as pqc_hash
from pqconnect.common.crypto import stream_kdf


class TestKDF(TestCase):
    def setUp(self) -> None:
        pass

    def tearDown(self) -> None:
        pass

    def test_stream_kdf(self) -> None:
        vectors = [
            {"n": 0, "k": b"\x00" * 32, "inpt": None, "res": []},
            {
                "n": 1,
                "k": b"\x00" * 32,
                "inpt": None,
                "res": [
                    b"v\xb8\xe0\xad\xa0\xf1=\x90@]j\xe5S\x86\xbd(\xbd\xd2\x19\xb8\xa0\x8d\xed\x1a\xa86\xef\xcc\x8bw\r\xc7"
                ],
            },
            {
                "n": 2,
                "k": b"\x00" * 32,
                "inpt": None,
                "res": [
                    b"v\xb8\xe0\xad\xa0\xf1=\x90@]j\xe5S\x86\xbd(\xbd\xd2\x19\xb8\xa0\x8d\xed\x1a\xa86\xef\xcc\x8bw\r\xc7",
                    b"\xdaAY|QWH\x8dw$\xe0?\xb8\xd8J7jC\xb8\xf4\x15\x18\xa1\x1c\xc3\x87\xb6i\xb2\xeee\x86",
                ],
            },
            {
                "n": 20,
                "k": b"\x00" * 32,
                "inpt": None,
                "res": [
                    b"v\xb8\xe0\xad\xa0\xf1=\x90@]j\xe5S\x86\xbd(\xbd\xd2\x19\xb8\xa0\x8d\xed\x1a\xa86\xef\xcc\x8bw\r\xc7",
                    b"\xdaAY|QWH\x8dw$\xe0?\xb8\xd8J7jC\xb8\xf4\x15\x18\xa1\x1c\xc3\x87\xb6i\xb2\xeee\x86",
                    b"\x9f\x07\xe7\xbeUQ8z\x98\xba\x97|s-\x08\r\xcb\x0f)\xa0H\xe3ei\x12\xc6S>2\xeez\xed",
                    b")\xb7!v\x9c\xe6NC\xd5q3\xb0t\xd89\xd51\xed\x1f(Q\n\xfbE\xac\xe1\n\x1fKyMo",
                    b"-\t\xa0\xe6c&l\xe1\xae~\xd1\x08\x19h\xa0u\x8eq\x8e\x99{\xd3b\xc6\xb0\xc3F4\xa9\xa0\xb3]",
                    b"\x01'7h\x1f{]\x0f(\x1e:\xfd\xe4X\xbc\x1es\xd2\xd3\x13\xc9\xcf\x94\xc0_\xf3qb@\xa2H\xf2",
                    b"\x13 \xa0X\xd7\xb3Vk\xd5 \xda\xaa>\xd2\xbf\n\xc5\xb8\xb1 \xfb\x85's\xc3c\x974\xb4\\\x91\xa4",
                    b"-\xd4\xcb\x83\xf8\x84\r.\xed\xb1X\x13\x10b\xac?\x1f,\xf8\xffm\xcd\x18V\xe8j\x1el1g\x16~",
                    b"\xe5\xa6\x88t+G\xc5\xad\xfbY\xd4\xdfv\xfd\x1d\xb1\xe5\x1e\xe0;\x1c\xa9\xf8*\xca\x17>\xdb\x8br\x93G",
                    b"N\xbe\x98\x0f\x90M\x10\xc9\x16D+G\x83\xa0\xe9\x84\x86\x0c\xb6\xc9W\xb3\x9c8\xed\x8fQ\xcf\xfa\xa6\x8aM",
                    b"\xe0\x10%\xa3\x9cPEF\xb9\xdc\x14\x06\xa7\xeb(\x15\x1eQP\xd7\xb2\x04\xba\xa7\x19\xd4\xf0\x91\x02\x12\x17\xdb",
                    b"\\\xf1\xb5\xc8LO\xa7\x1a\x87\x96\x10\xa1\xa6\x95\xacR|[VwJk\x8a!\xaa\xe8\x86\x85\x86\x8e\tL",
                    b"\xf2\x9e\xf4\t\n\xf7\xa9\x0c\xc0~\x88\x17\xaaR\x87cy}<3+g\xcaK\xc1\x10d,!Q\xecG",
                    b"\xee\x84\xcb\x8cB\xd8_\x10\xe2\xa8\xcb\x18\xc3\xb73_&\xe8\xc3\x9a\x12\xb1\xbc\xc1pqw\xb7a8s.",
                    b"\xed\xaa\xb7M\xa1A\x0f\xc0U\xea\x06\x8c\x99\xe9&\n\xcb\xe37\xcf]>\x00\xe5\xb3#\x0f\xfe\xdb\x0b\x99\x07",
                    b"\x87\xd0\xc7\x0e\x0b\xfeA\x98\xeagX\xddZa\xfb_\xec-\xf9\x81\xf3\x1b\xef\xe1S\xf8\x1d\x17\x16\x17\x84\xdb",
                    b'\x1c\x88"\xd5<\xd1\xee}\xb526H(\xbd\xf4\x04\xb0@\xa8\xdc\xc5"\xf3\xd3\xd9\x9a\xecK\x80W\xed\xb8',
                    b"P\t1\xa2\xc4-/\x0cW\x08G\x10\x0bWT\xda\xfc_\xbd\xb8\x94\xbb\xef\x1a-\xe1\xa0\x7f\x8b\xa0\xc4\xb9",
                    b"\x190\x10f\xed\xbc\x05k{H\x1ez\x0cF){\xbbX\x9d\x9d\xa5\xb6u\xa6r>\x15.^c\xa4\xce",
                    b"\x03N\x9e\x83\xe5\x8a\x01:\xf0\xe75/\xb7\x90\x85\x14\xe3\xb3\xd1\x04\r\x0b\xb9c\xb3\x95Kck_\xd4\xbf",
                ],
            },
            {
                "n": 1,
                "k": b"\x00" * 32,
                "inpt": b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
                + b"\x00" * 16,
                "res": [
                    b"\x8ac\xc7\xf8\xae\x1fH\x11+-S\xe0r\x85b?\xde\xbf%\xcfc\xfa\xc4\xa8\x07\xe8\x89\xd2\x84\xef\x95N"
                ],
            },
        ]

        self.assertTrue(
            all(
                [
                    stream_kdf(vec["n"], vec["k"], vec["inpt"]) == vec["res"]
                    for vec in vectors
                ]
            )
        )

    def test_stream_kdf_wrong_key_type(self) -> None:
        try:
            stream_kdf(1, "h" * 32)
        except Exception:
            self.assertTrue(True)
            return

        self.assertTrue(False, "exception was not thrown")

    def test_stream_kdf_wrong_key_len(self) -> None:
        try:
            stream_kdf(1, b"h" * 2)
        except Exception:
            self.assertTrue(True)
            return

        self.assertTrue(False, "exception was not thrown")

    def test_stream_kdf_wrong_inpt_type(self) -> None:
        try:
            stream_kdf(1, b"h" * 32, "hi" * 16)
        except Exception:
            self.assertTrue(True)
            return

        self.assertTrue(False, "exception was not thrown")

    def test_stream_kdf_wrong_inpt_len(self) -> None:
        try:
            stream_kdf(1, b"h" * 32, b"hi" * 15)
        except Exception:
            self.assertTrue(True)
            return

        self.assertTrue(False, "exception was not thrown")

    def test_pqc_hash(self) -> None:
        vectors = [
            (
                b"",
                b"F\xb9\xdd+\x0b\xa8\x8d\x13#;?\xebt>\xeb$?\xcdR\xeab\xb8\x1b\x82\xb5\x0c'dn\xd5v/",
            ),
            (
                b"0123456789abcdef",
                b"\xf2\x05\xe4H\xf1?u\xe2B\xc27\xac\x0c\x15\x05\xb0\x02\x0c\xde[\x8b\xd5\xe6\xf0\xb0\\DB\x99\x81\x7f\xf7",
            ),
            (
                (
                    b"'Twas brillig, and the slithy toves\n"
                    b"Did gyre and gimble in the wabe;\n"
                    b"All mimsy were the borogoves,\n"
                    b"And the mome raths outgrabe."
                ),
                b"s\x89\x98y\xf19H7NIo}*\x10\x16\x004W\x0c\x89\xca\x1bw\x82\x9c\x8e5U)dq\xb6",
            ),
        ]

        self.assertTrue(all([pqc_hash(a) == b for a, b in vectors]))


if __name__ == "__main__":
    main()
