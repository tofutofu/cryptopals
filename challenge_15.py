# PKCS#7 padding validation

# Validation is fine. But it's problematic when an attacker can
# probe a server as oracle and get to know that pkcs7 validation failed
# (rather than that some general unspecific error occurred). And it's much
# worse, if an attacker can get to see any of the exception messages
# below (since they could reveal parts of a plaintext that should remain hidden)!


def validate_pkcs7(s: bytes, blocksize: int = 16):
    r"""
    Validate PKCS#7 padding on input plaintext bytes.

    >>> from challenge_09 import pkcs7
    >>> s = b"ICE ICE BABY"
    >>> pkcs7(s)
    b'ICE ICE BABY\x04\x04\x04\x04'

    >>> s = b"ICE ICE BABY\x04\x04\x04\x04"
    >>> validate_pkcs7(s)
    True

    >>> s = b"ICE ICE BABY\x05\x05\x05\x05"
    >>> validate_pkcs7(s)
    Traceback (most recent call last):
      ...
    ValueError: Plaintext has invalid padding: b'ICE ICE BABY\x05\x05\x05\x05'

    >>> s = b"ICE ICE BABY\x01\x02\x03\x04"
    >>> validate_pkcs7(s)
    Traceback (most recent call last):
      ...
    ValueError: Plaintext has invalid padding: b'ICE ICE BABY\x01\x02\x03\x04'

    >>> s = b"ICE ICE BABY\x01\x02\x03\xFF"
    >>> validate_pkcs7(s)
    Traceback (most recent call last):
      ...
    ValueError: Last byte of plain text (0xFF) is not in range 1 to 16
    """

    nbytes = len(s)

    if len(s) == 0:
        raise ValueError("Plaintext is empty")

    if nbytes % blocksize != 0:
        raise ValueError(
            f"Plaintext length ({nbytes}) is not a multiple of block_size {blocksize}"
        )

    tail = list(s[-blocksize:])
    pad_byte = tail[-1]
    if pad_byte > blocksize:
        raise ValueError(
            f"Last byte of plain text (0x{pad_byte:02X}) is not in range 1 to {blocksize}"
        )

    expected = [pad_byte] * pad_byte
    if tail[-pad_byte:] != expected:
        # NOTE: This message is debliberately leaking information.
        # In a real system, this error message could be a security risk since it
        # can reveal things to an attacker.
        raise ValueError(f"Plaintext has invalid padding: {bytes(tail)!r}")

    return True


if __name__ == "__main__":
    import doctest

    doctest.testmod()
