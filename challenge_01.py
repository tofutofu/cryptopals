# https://cryptopals.com/sets/1/challenges/1

from base64 import b64encode

#
# The hex-to-base64 function is actually never used in any of the following challenges.
#


def hex_to_base64(hex_str: bytes) -> bytes:
    """
    >>> hex_str = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    >>> hex_to_base64(hex_str)
    b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    """
    res = []
    x = int(hex_str, 16)
    while x:
        res.append(x & 0xFF)
        x >>= 8
    return b64encode(bytes(res[::-1]))


def hex_to_base64_alt(hex_str: bytes) -> bytes:
    """
    >>> hex_str = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    >>> hex_to_base64_alt(hex_str)
    b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    """
    return b64encode(
        bytes(int(hex_str[i : i + 2], 16) for i in range(0, len(hex_str), 2))
    )


#
# The following functions are useful, however.
#
# Note: The docstrings for doctest need to be raw-strings (or escape the
# backslashes), otherwise doctest errors because they contain null bytes!


def bytes_to_hex(s: bytes | list[int], blocksize: int = 0) -> str:
    r"""
    Convert a real bytes string into a prettier hex-string.

    >>> s = b'\x04\x04ABC\x00\x07'
    >>> bytes_to_hex(s)
    '04044142430007'
    >>> s = b'\x00\x07ABBABAAB\x00\x07'
    >>> bytes_to_hex(s, 2)
    '0007 4142 4241 4241 4142 0007'
    """
    res = "".join(f"{z:02x}" for z in s)
    if not blocksize:
        return res
    return " ".join(
        res[i : i + 2 * blocksize] for i in range(0, len(res), 2 * blocksize)
    )


def hex_to_bytes(s: str) -> bytes:
    r"""
    Convert a pretty hex-string into a real bytes string.

    >>> s = '04044142430007'
    >>> hex_to_bytes(s)
    b'\x04\x04ABC\x00\x07'
    >>> s = '0404 4142 4300 07'
    >>> hex_to_bytes(s)
    b'\x04\x04ABC\x00\x07'
    """
    s = s.replace(" ", "")
    return bytes(int(s[i : i + 2], 16) for i in range(0, len(s), 2))


if __name__ == "__main__":
    import doctest

    doctest.testmod()
