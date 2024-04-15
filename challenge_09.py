# PKCS#7 padding

# RFC-2315 definition
# https://datatracker.ietf.org/doc/html/rfc2315#section-10.3


def pkcs7(s: bytes, blocksize: int = 16) -> bytes:
    r"""
    Apply PKC#7 padding to bytes string s.

    The input string is padded with (blocksize - (len(s) % blocksize)) pad bytes.
    The value of the pad byte is equal to the length of the padding. For instance,
    if 4 pad bytes are needed, then the pad byte is b'\0x04'.

    Each input string is padded. If len(s) % blocksize == 0, then blocksize padding
    bytes are added. Since each input is padded and no padding string is a suffix of
    any other, it's then always possible to unambiguously remove padding later.

    >>> s = b"YELLOW SUBMARINE"
    >>> pkcs7(s, 20)
    b'YELLOW SUBMARINE\x04\x04\x04\x04'
    >>> pkcs7(s, 16)
    b'YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'
    """
    assert 0 < blocksize < 0xFF

    pad_byte = blocksize - (len(s) % blocksize)
    return s + bytes([pad_byte] * pad_byte)


if __name__ == "__main__":
    import doctest

    doctest.testmod()
