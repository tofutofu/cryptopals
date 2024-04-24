# Implement a SHA-1 keyed MAC

# SHA-1
#
# Definition of the standard
# https://csrc.nist.gov/files/pubs/fips/180-4/final/docs/draft-fips180-4_feb2011.pdf
#
# Short overview
# https://hamishgibbs.net/pages/understanding-sha-1-with-python/
#
# First collision report
# https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html
#
# Download the implementation from The Algorithms:
# https://github.com/TheAlgorithms/Python/blob/3925b8155bebd84eababfba0f5a12e5129cfaa44/hashes/sha1.py

# From Wikipedia (https://en.wikipedia.org/wiki/Message_authentication_code):
#
#     A secure message authentication code must resist attempts by an adversary to forge tags,
#     for arbitrary, select, or all messages, including under conditions of known- or
#     chosen-message. It should be computationally infeasible to compute a valid tag of the
#     given message without knowledge of the key.
#

from os import urandom

import sha1


def generate(n: int) -> bytes:
    """
    Generate a new random key (n bytes).
    """
    return urandom(n)


def sign(msg: bytes, key: bytes) -> str:
    """
    Generate MAC (message authentication code), given a message and a key.
    """
    return sha1.SHA1Hash(key + msg).final_hash()


def verify(msg: bytes, tag: str | bytes, key: bytes) -> bool:
    """
    Verify integrity of the message, given a MAC (tag) and a key.
    """
    if isinstance(tag, str):
        return sha1.SHA1Hash(key + msg).final_hash() == tag
    elif isinstance(tag, bytes):
        return hex_to_bytes(sha1.SHA1Hash(key + msg).final_hash()) == tag
    else:
        raise TypeError(
            f"Expected 'tag' to be a str or bytes, but got a {tag.__class__.__name__}"
        )


def hex_to_bytes(s: str) -> bytes:
    x = int(s, 16)
    b = []
    while x:
        b.append(x & 0xFF)
        x >>= 8
    b += [0] * (20 - len(b))
    return bytes(b[::-1])


def test():
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


if __name__ == "__main__":
    test()
