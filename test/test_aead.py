import unittest

from pqconnect.common.crypto import (
    KLEN,
    NLEN,
    TAGLEN,
    secret_box,
    secret_unbox,
)


class TestAEAD(unittest.TestCase):
    def test_aead(self) -> None:
        r"""Test vector from RFC 8439 Appendix A.5:

        Below we see decrypting a message.  We receive a ciphertext, a nonce,
        and a tag.  We know the key.  We will check the tag and then (assuming
        that it validates) decrypt the ciphertext.  In this particular
        protocol, we'll assume that there is no padding of the plaintext.

        The ChaCha20 Key
        000  1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0  ..@..U...3......
        016  47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0  G9..@+....\. pu.

        Ciphertext:
        000  64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd  d...u...`.b...C.
        016  5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2  ^.\.4\....g..l..
        032  4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0  Ll..u]C....N8-&.
        048  bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf  ...<2.....;.5X..
        064  33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81  3/..q......J....
        080  14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55  ...n..3.`....7.U
        096  97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38  ...n...a..2N+5.8
        112  36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4  6..{j|.....{S.g.
        128  b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9  ..lv{.MF..R.....
        144  90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e  .@...3"^.....lR>
        160  af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a  .E4..?..[.Gq..Tj
        176  0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a  ..+..VN..B"s.H'.
        192  0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e  ..1`S.v..U..1YCN
        208  ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10  ..NFm.Z.s.rv'.z.
        224  49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30  I....6...h..w.q0
        240  30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29  0[.......{qMlo,)
        256  a6 ad 5c b4 02 2b 02 70 9b                       ..\..+.p.

        The nonce:
        000  00 00 00 00 01 02 03 04 05 06 07 08              ............

        The AAD:
        000  f3 33 88 86 00 00 00 00 00 00 4e 91              .3........N.

        Received Tag:
        000  ee ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38  ...g..."9#6....8


        First, we calculate the one-time Poly1305 key

          ChaCha state with key setup
              61707865  3320646e  79622d32  6b206574
              a540921c  8ad355eb  868833f3  f0b5f604
              c1173947  09802b40  bc5cca9d  c0757020
              00000000  00000000  04030201  08070605

          ChaCha state after 20 rounds
              a94af0bd  89dee45c  b64bb195  afec8fa1
              508f4726  63f554c0  1ea2c0db  aa721526
              11b1e514  a0bacc0f  828a6015  d7825481
              e8a4a850  d9dcbbd6  4c2de33a  f8ccd912

         out bytes:
        bd:f0:4a:a9:5c:e4:de:89:95:b1:4b:b6:a1:8f:ec:af:
        26:47:8f:50:c0:54:f5:63:db:c0:a2:1e:26:15:72:aa

        Poly1305 one-time key:
        000  bd f0 4a a9 5c e4 de 89 95 b1 4b b6 a1 8f ec af  ..J.\.....K.....
        016  26 47 8f 50 c0 54 f5 63 db c0 a2 1e 26 15 72 aa  &G.P.T.c....&.r.

         Next, we construct the AEAD buffer

        Poly1305 Input:
        000  f3 33 88 86 00 00 00 00 00 00 4e 91 00 00 00 00  .3........N.....
        016  64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd  d...u...`.b...C.
        032  5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2  ^.\.4\....g..l..
        048  4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0  Ll..u]C....N8-&.
        064  bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf  ...<2.....;.5X..
        080  33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81  3/..q......J....
        096  14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55  ...n..3.`....7.U
        112  97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38  ...n...a..2N+5.8
        128  36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4  6..{j|.....{S.g.
        144  b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9  ..lv{.MF..R.....
        160  90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e  .@...3"^.....lR>
        176  af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a  .E4..?..[.Gq..Tj
        192  0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a  ..+..VN..B"s.H'.
        208  0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e  ..1`S.v..U..1YCN
        224  ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10  ..NFm.Z.s.rv'.z.
        240  49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30  I....6...h..w.q0
        256  30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29  0[.......{qMlo,)
        272  a6 ad 5c b4 02 2b 02 70 9b 00 00 00 00 00 00 00  ..\..+.p........
        288  0c 00 00 00 00 00 00 00 09 01 00 00 00 00 00 00  ................

          We calculate the Poly1305 tag and find that it matches

        Calculated Tag:
        000  ee ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38  ...g..."9#6....8

         Finally, we decrypt the ciphertext

        Plaintext::
        000  49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 73 20  Internet-Drafts
        016  61 72 65 20 64 72 61 66 74 20 64 6f 63 75 6d 65  are draft docume
        032  6e 74 73 20 76 61 6c 69 64 20 66 6f 72 20 61 20  nts valid for a
        048  6d 61 78 69 6d 75 6d 20 6f 66 20 73 69 78 20 6d  maximum of six m
        064  6f 6e 74 68 73 20 61 6e 64 20 6d 61 79 20 62 65  onths and may be
        080  20 75 70 64 61 74 65 64 2c 20 72 65 70 6c 61 63   updated, replac
        096  65 64 2c 20 6f 72 20 6f 62 73 6f 6c 65 74 65 64  ed, or obsoleted
        112  20 62 79 20 6f 74 68 65 72 20 64 6f 63 75 6d 65   by other docume
        128  6e 74 73 20 61 74 20 61 6e 79 20 74 69 6d 65 2e  nts at any time.
        144  20 49 74 20 69 73 20 69 6e 61 70 70 72 6f 70 72   It is inappropr
        160  69 61 74 65 20 74 6f 20 75 73 65 20 49 6e 74 65  iate to use Inte
        176  72 6e 65 74 2d 44 72 61 66 74 73 20 61 73 20 72  rnet-Drafts as r
        192  65 66 65 72 65 6e 63 65 20 6d 61 74 65 72 69 61  eference materia
        208  6c 20 6f 72 20 74 6f 20 63 69 74 65 20 74 68 65  l or to cite the
        224  6d 20 6f 74 68 65 72 20 74 68 61 6e 20 61 73 20  m other than as
        240  2f e2 80 9c 77 6f 72 6b 20 69 6e 20 70 72 6f 67  /...work in prog
        256  72 65 73 73 2e 2f e2 80 9d                       ress./...

        """

        k = bytes.fromhex(
            "1c 92 40 a5 eb 55 d3 8a \
            f3 33 88 86 04 f6 b5 f0 \
            47 39 17 c1 40 2b 80 09 \
            9d ca 5c bc 20 70 75 c0"
        )

        n = bytes.fromhex("00 00 00 00 01 02 03 04 05 06 07 08")

        ad = bytes.fromhex("f3 33 88 86 00 00 00 00 00 00 4e 91")

        tag = bytes.fromhex("ee ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38")

        ct = bytes.fromhex(
            "64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd \
            5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2 \
            4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0 \
            bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf \
            33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81 \
            14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55 \
            97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38 \
            36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4 \
            b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9 \
            90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e \
            af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a \
            0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a \
            0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e \
            ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10 \
            49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30 \
            30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29 \
            a6 ad 5c b4 02 2b 02 70 9b"
        )

        msg = bytes.fromhex(
            "49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 73 20 \
            61 72 65 20 64 72 61 66 74 20 64 6f 63 75 6d 65 \
            6e 74 73 20 76 61 6c 69 64 20 66 6f 72 20 61 20 \
            6d 61 78 69 6d 75 6d 20 6f 66 20 73 69 78 20 6d \
            6f 6e 74 68 73 20 61 6e 64 20 6d 61 79 20 62 65 \
            20 75 70 64 61 74 65 64 2c 20 72 65 70 6c 61 63 \
            65 64 2c 20 6f 72 20 6f 62 73 6f 6c 65 74 65 64 \
            20 62 79 20 6f 74 68 65 72 20 64 6f 63 75 6d 65 \
            6e 74 73 20 61 74 20 61 6e 79 20 74 69 6d 65 2e \
            20 49 74 20 69 73 20 69 6e 61 70 70 72 6f 70 72 \
            69 61 74 65 20 74 6f 20 75 73 65 20 49 6e 74 65 \
            72 6e 65 74 2d 44 72 61 66 74 73 20 61 73 20 72 \
            65 66 65 72 65 6e 63 65 20 6d 61 74 65 72 69 61 \
            6c 20 6f 72 20 74 6f 20 63 69 74 65 20 74 68 65 \
            6d 20 6f 74 68 65 72 20 74 68 61 6e 20 61 73 20 \
            2f e2 80 9c 77 6f 72 6b 20 69 6e 20 70 72 6f 67 \
            72 65 73 73 2e 2f e2 80 9d"
        )

        poly1305_input = bytes.fromhex(
            "f3 33 88 86 00 00 00 00 00 00 4e 91 00 00 00 00 \
            64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd \
            5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2 \
            4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0 \
            bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf \
            33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81 \
            14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55 \
            97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38 \
            36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4 \
            b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9 \
            90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e \
            af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a \
            0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a \
            0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e \
            ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10 \
            49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30 \
            30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29 \
            a6 ad 5c b4 02 2b 02 70 9b 00 00 00 00 00 00 00 \
            0c 00 00 00 00 00 00 00 09 01 00 00 00 00 00 00"
        )

        self.assertEqual((ct, tag), secret_box(k, n, msg, ad))
        self.assertEqual(msg, secret_unbox(k, n, tag, ct, ad))

    def test_bad_input(self) -> None:
        succeed = False

        # wrong key length
        try:
            secret_box(b"0", b"0" * NLEN, b"fail" * 32)

        except ValueError:
            succeed = True

        self.assertTrue(succeed, "klen")
        succeed = False

        # wrong nonce length
        try:
            secret_box(b"*" * KLEN, b"0", b"fail" * 32)

        except ValueError:
            succeed = True

        self.assertTrue(succeed, "nlen")

        # wrong tag length
        succeed = False
        try:
            secret_unbox(b"0" * KLEN, b"0" * NLEN, b"f" * 12, b"fail" * 32)

        except ValueError:
            succeed = True

        self.assertTrue(succeed, "tag len")

        # wrong nonce length
        succeed = False
        try:
            secret_unbox(b"0" * KLEN, b"0" * 5, b"f" * TAGLEN, b"fail" * 32)

        except ValueError:
            succeed = True

        self.assertTrue(succeed, "nonce len")

        # wrong key length
        succeed = False
        try:
            secret_unbox(b"0" * 31, b"0" * NLEN, b"f" * TAGLEN, b"fail" * 32)

        except ValueError:
            succeed = True

        self.assertTrue(succeed, "key len")

        # decryption failure
        succeed = False
        try:
            secret_unbox(b"8" * KLEN, b"8" * NLEN, b"3" * TAGLEN, b"fail" * 32)

        except Exception:
            succeed = True

        self.assertTrue(succeed, "Decryption failure")


if __name__ == "__main__":
    unittest.main()
