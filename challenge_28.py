# SHA-1/Implement a SHA-1 keyed MAC

# SHA-1
# -----
#
# Definition of the standard
# https://csrc.nist.gov/files/pubs/fips/180-4/final/docs/draft-fips180-4_feb2011.pdf
#
# Short overview (without technical details)
# https://hamishgibbs.net/pages/understanding-sha-1-with-python/
#
# First collision report (2017)
# https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html
#
# A pure-Python implementation of SHA-1 can also be found in The Algorithms:
# https://github.com/TheAlgorithms/Python/blob/3925b8155bebd84eababfba0f5a12e5129cfaa44/hashes/sha1.py
#
# I decided to implement it myself, based on the FIPS document and Wikipedia
# to get a better understanding how all the parts fit together.
#
# MAC
# ---
#
# From Wikipedia (https://en.wikipedia.org/wiki/Message_authentication_code):
#
#     A secure message authentication code must resist attempts by an adversary to forge tags,
#     for arbitrary, select, or all messages, including under conditions of known- or
#     chosen-message. It should be computationally infeasible to compute a valid tag of the
#     given message without knowledge of the key.
#


from os import urandom
import struct


def sha1(
    msg: bytes, rt: type | None = None, hh: str | int | None = None, msg_len: int = 0
) -> str | bytes | int:
    """
    Calculate the SHA-1 hash for a bytes string.

    Returns the hash value as hexdigest if `rt` is None. Otherwise, as Python integer.
    Arguments `hh` and `msg_len` can be used to initialize the running state (the initial
    hash values) and simulate a different message length.

    The returned SHA-1 hash value has length 160 bits (20 bytes).
    The internal block size is 512 bits (64 bytes).

    Example:

    >>> s = b'SHA-1 is vulnerable against chosen-prefix attacks'
    >>> sha1(s)
    '5d395522a042d7883ad0f221746a2b13cadfb5e4'
    >>> hex(sha1(s, rt=int))
    '0x5d395522a042d7883ad0f221746a2b13cadfb5e4'
    >>> import hashlib
    >>> assert sha1(s) == hashlib.sha1(s).hexdigest()
    >>> s = b''
    >>> assert sha1(s) == hashlib.sha1(s).hexdigest()
    >>> s = b'A' * 80 + b'Test'
    >>> assert sha1(s) == hashlib.sha1(s).hexdigest()
    """

    if isinstance(msg, str):
        raise TypeError("Strings must be encoded as bytes before hashing")

    def rotl(x: int, n: int = 1) -> int:
        return u32((x << n) | (x >> (32 - n)))

    def not_(x: int) -> int:
        return x ^ 0xFFFF_FFFF

    # Length of message should be smaller than 2**64 bits
    assert len(msg) < (1 << 61)

    # initialize running state
    if hh is not None:
        if isinstance(hh, str):
            hh = int(hh, 16)
        h0 = u32(hh >> 128)
        h1 = u32(hh >> 96)
        h2 = u32(hh >> 64)
        h3 = u32(hh >> 32)
        h4 = u32(hh)
    else:
        h0 = 0x67452301
        h1 = 0xEFCDAB89
        h2 = 0x98BADCFE
        h3 = 0x10325476
        h4 = 0xC3D2E1F0

    # add padding
    msg += padding(msg_len or len(msg))

    # compress each block - iterates over the 512-bit (64-byte) blocks
    for i in range(0, len(msg), 64):
        block = msg[i : i + 64]

        # break block into 16 words (32-bit unsigned integers)
        words = [int.from_bytes(block[j : j + 4]) for j in range(0, 64, 4)]

        # prepare message schedule (expand 16 words to 80 words)
        for j in range(16, 80):
            w = rotl(words[j - 3] ^ words[j - 8] ^ words[j - 14] ^ words[j - 16])
            words.append(w)

        # initialize hash values for block
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        # main loop - iterate over words[j]
        # f is a non-linear function
        for j in range(80):
            if j < 20:
                f = (b & c) | (not_(b) & d)  # Ch
                k = 0x5A827999
            elif j < 40:
                f = b ^ c ^ d  # Parity
                k = 0x6ED9EBA1
            elif j < 60:
                f = (b & c) | (b & d) | (c & d)  # Maj
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d  # Parity
                k = 0xCA62C1D6

            # tmp is needed, since it depends on e
            tmp = u32(words[j] + rotl(a, 5) + f + e + k)
            e = d
            d = c
            c = rotl(b, 30)
            b = a
            a = tmp

        # update "running state" (intermediate hash values) for message
        h0 = u32(h0 + a)
        h1 = u32(h1 + b)
        h2 = u32(h2 + c)
        h3 = u32(h3 + d)
        h4 = u32(h4 + e)

    # calculate final hash value (160-bit unsigned integer)
    hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4

    if rt is None or rt is str:  # hexdigest
        return f"{hh:040x}"
    if rt is bytes:  # raw binary digest
        return hh.to_bytes(20)
    return hh


def padding(msg_len: int) -> bytes:
    """
    SHA-1 padding.

    - Append bit 1.
    - Append k bits 0.
    - Append the message length in bits as 64-bit big-endian integer.
    - Ensure that the total length equals a multiple of 64 bytes (512 bits).

    If ml is the message length in bits, then k should be the smallest
    non-negative integer such that

      ml + 1 + k + 64 ≡ 0 mod 512

    """
    n = msg_len + 1 + 8
    k = 64 - (n % 64)
    if k == 64:
        k = 0

    padding = b"\x80"
    padding += b"\x00" * k
    padding += struct.pack(">Q", msg_len << 3)
    assert (msg_len + len(padding)) % 64 == 0
    return padding


def u32(x: int) -> int:
    return x & 0xFFFF_FFFF


def generate(n: int) -> bytes:
    """
    Generate a new random key (n bytes).
    """
    return urandom(n)


def sign(msg: bytes, key: bytes) -> str:
    """
    Generate MAC (message authentication code), given a message and a key.
    """
    return sha1(key + msg)  # type: ignore


def verify(msg: bytes, tag: str | bytes | int, key: bytes) -> bool:
    """
    Verify integrity of the message, given a MAC (tag) and a key.
    """
    if isinstance(tag, str):
        return sha1(key + msg) == tag
    elif isinstance(tag, bytes):
        return sha1(key + msg, rt=int).to_bytes(20) == tag  # type: ignore
    elif isinstance(tag, int):
        return sha1(key + msg, rt=int) == tag
    else:
        raise TypeError(
            f"Expected 'tag' to be a str, bytes or int, but got a {tag.__class__.__name__}"
        )


def test1():
    msg = b"Yellow mellow"
    key = generate(20)
    tag = sign(msg, key)
    assert verify(msg, tag, key)

    # other key
    key1 = bytearray(key)
    key1[-1] ^= 1
    key1 = bytes(key1)
    assert not verify(msg, tag, key1)

    # other tag
    tag1 = tag[:-1] + "1" if tag[-1] == "0" else "0"
    assert not verify(msg, tag1, key)

    # other message
    msg1 = b"Yellow melloo"
    assert not verify(msg1, tag, key)

    return True


def test2():
    s1 = b"ABC"
    s2 = b"XYZ"
    p1 = padding(len(s1))

    hh = sha1(s1, rt=int)

    target = sha1(s1 + p1 + s2)
    actual = sha1(s2, hh=hh, msg_len=len(s1 + p1 + s2))

    assert actual == target


if __name__ == "__main__":
    test1()
    test2()
