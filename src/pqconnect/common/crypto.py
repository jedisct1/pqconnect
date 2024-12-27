from hashlib import shake_256

import py25519
from pymceliece import mceliece6960119
from pyntruprime import sntrup761
from pysodium import (
    crypto_aead_chacha20poly1305_ietf_ABYTES,
    crypto_aead_chacha20poly1305_ietf_decrypt_detached,
    crypto_aead_chacha20poly1305_ietf_encrypt_detached,
    crypto_aead_chacha20poly1305_ietf_KEYBYTES,
    crypto_aead_chacha20poly1305_ietf_NONCEBYTES,
    crypto_stream_chacha20_xor_ic,
)
from pysodium import randombytes as rb

# crypto settings
stream_xor_ic = crypto_stream_chacha20_xor_ic
KLEN = crypto_aead_chacha20poly1305_ietf_KEYBYTES
NLEN = crypto_aead_chacha20poly1305_ietf_NONCEBYTES
skem = mceliece6960119
ekem = sntrup761
TAGLEN = crypto_aead_chacha20poly1305_ietf_ABYTES
randombytes = rb
HLEN = 32
dh = py25519


def secret_box(
    key: bytes, nonce: bytes, msg: bytes, ad: bytes = b""
) -> tuple[bytes, bytes]:
    """key: 32 byte encryption key
    nonce: 8 byte nonce
    msg: bytes to be encrypted and authenticated
    ad: bytes to be authenticated

    Described in described in https://tools.ietf.org/html/rfc8439
     Section 2.8.  AEAD Construction

    AEAD_CHACHA20_POLY1305 is an authenticated encryption with additional
    data algorithm.  The inputs to AEAD_CHACHA20_POLY1305 are:

    o  A 256-bit key

    o  A 96-bit nonce -- different for each invocation with the same key

    o  An arbitrary length plaintext

    o  Arbitrary length additional authenticated data (AAD)

    Some protocols may have unique per-invocation inputs that are not 96
    bits in length.  For example, IPsec may specify a 64-bit nonce.  In
    such a case, it is up to the protocol document to define how to
    transform the protocol nonce into a 96-bit nonce, for example, by
    concatenating a constant value.

    The ChaCha20 and Poly1305 primitives are combined into an AEAD that
    takes a 256-bit key and 96-bit nonce as follows:

    o  First, a Poly1305 one-time key is generated from the 256-bit key
       and nonce using the procedure described in Section 2.6.

    o  Next, the ChaCha20 encryption function is called to encrypt the
       plaintext, using the same key and nonce, and with the initial
       counter set to 1.

    o  Finally, the Poly1305 function is called with the Poly1305 key
       calculated above, and a message constructed as a concatenation of
       the following:

       *  The AAD

       *  padding1 -- the padding is up to 15 zero bytes, and it brings
          the total length so far to an integral multiple of 16.  If the
          length of the AAD was already an integral multiple of 16 bytes,
          this field is zero-length.

       *  The ciphertext

       *  padding2 -- the padding is up to 15 zero bytes, and it brings
          the total length so far to an integral multiple of 16.  If the
          length of the ciphertext was already an integral multiple of 16
          bytes, this field is zero-length.

       *  The length of the additional data in octets (as a 64-bit
          little-endian integer).

       *  The length of the ciphertext in octets (as a 64-bit little-
          endian integer).

    The output from the AEAD is the concatenation of:

    o  A ciphertext of the same length as the plaintext.

    o  A 128-bit tag, which is the output of the Poly1305 function.


    """
    return crypto_aead_chacha20poly1305_ietf_encrypt_detached(
        msg, ad, nonce, key
    )


def secret_unbox(
    key: bytes, nonce: bytes, tag: bytes, ct: bytes, ad: bytes = b""
) -> bytes:
    """
    secret_unbox takes a key, nonce, associated data, ciphertext, and tag,
    verifies the tag, and if successful decrypts the ciphertext under the given
    key and nonce, returning the plaintext.

    If verification fails an exception is raised.

    Again from the RFC:
    "Decryption is similar with the following differences:

    o  The roles of ciphertext and plaintext are reversed, so the
       ChaCha20 encryption function is applied to the ciphertext,
       producing the plaintext.

    o  The Poly1305 function is still run on the AAD and the ciphertext,
       not the plaintext.

    o  The calculated tag is bitwise compared to the received tag.  The
       message is authenticated if and only if the tags match.

    A few notes about this design:

    1.  The amount of encrypted data possible in a single invocation is
        2^32-1 blocks of 64 bytes each, because of the size of the block
        counter field in the ChaCha20 block function.  This gives a total
        of 274,877,906,880 bytes, or nearly 256 GB.  This should be
        enough for traffic protocols such as IPsec and TLS, but may be
        too small for file and/or disk encryption.  For such uses, we can
        return to the original design, reduce the nonce to 64 bits, and
        use the integer at position 13 as the top 32 bits of a 64-bit
        block counter, increasing the total message size to over a
        million petabytes (1,180,591,620,717,411,303,360 bytes to be
        exact).

    2.  Despite the previous item, the ciphertext length field in the
        construction of the buffer on which Poly1305 runs limits the
        ciphertext (and hence, the plaintext) size to 2^64 bytes, or
        sixteen thousand petabytes (18,446,744,073,709,551,616 bytes to
        be exact).

    The AEAD construction in this section is a novel composition of
    ChaCha20 and Poly1305.  A security analysis of this composition is
    given in [Procter].

    Here is a list of the parameters for this construction as defined in
    Section 4 of [RFC5116]:

    o  K_LEN (key length) is 32 octets.

    o  P_MAX (maximum size of the plaintext) is 274,877,906,880 bytes, or
       nearly 256 GB.

    o  A_MAX (maximum size of the associated data) is set to 2^64-1
       octets by the length field for associated data.

    o  N_MIN = N_MAX = 12 octets.

    o  C_MAX = P_MAX + tag length = 274,877,906,896 octets.

    Distinct AAD inputs (as described in Section 3.3 of [RFC5116]) shall
    be concatenated into a single input to AEAD_CHACHA20_POLY1305.  It is
    up to the application to create a structure in the AAD input if it is
    needed."

    """

    return crypto_aead_chacha20poly1305_ietf_decrypt_detached(
        ct, tag, ad, nonce, key
    )


def stream_kdf(n: int, k: bytes, inpt: bytes = b"") -> list[bytes]:
    """Returns a length-n list of length-KLEN strings of pseudo-random
    bytes derived from key k

    If inpt is given, then first a new key k' is computed as the output of
    chacha under k and the first 16 bytes of inpt given as the combined counter
    and nonce. That is, the state of the cipher is initialized to

    |'expand 32-byte k'|
    | k[:16]           |
    | k[16:32]         |
    | inpt[:16]        |    # 8-byte counter || 8-byte nonce

    The first 256-bits of output of this stream are assigned to a new key k',
    and the process is repeated with the second 16 bytes of inpt and the new
    key, i.e.

    |'expand 32-byte k'|
    | k'[:16]          |
    | k'[16: 32]       |
    | inpt[16:32]      |

    This is then used to generate a stream from which new keys are derived.

    """

    if len(k) != KLEN or not isinstance(k, bytes):
        raise ValueError(f"k must be {KLEN} bytes")

    if inpt:
        if len(inpt) != KLEN or not isinstance(inpt, bytes):
            raise ValueError(f"inpt must be {KLEN} bytes")

        k = stream_xor_ic(
            b"\x00" * KLEN,  # Message
            inpt[8:16],  # nonce
            int.from_bytes(inpt[:8], "little"),  # Counter
            k,  # key
        )
        s = stream_xor_ic(
            b"\x00" * KLEN * n,  # Message
            inpt[24:],  # nonce
            int.from_bytes(inpt[16:24], "little"),  # counter
            k,
        )
    else:
        s = stream_xor_ic(b"\x00" * KLEN * n, b"\x00" * 8, 0, k)

    return [s[i * KLEN : (i + 1) * KLEN] for i in range(n)]


def h(x: bytes) -> bytes:
    ctx = shake_256()
    ctx.update(x)
    return ctx.digest(HLEN)
