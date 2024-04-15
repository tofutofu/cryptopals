# Fixed XOR

# The question suggests that pretty-printed hex strings should be taken as input.
# In general it may be more convenient to take real byte-strings as input.


def XOR(a: str | bytes, b: str | bytes) -> str:
    """
    >>> a = '1c0111001f010100061a024b53535009181c'
    >>> b = '686974207468652062756c6c277320657965'
    >>> XOR(a, b)
    '746865206b696420646f6e277420706c6179'
    >>> a = b'1c0111001f010100061a024b53535009181c'
    >>> b = b'686974207468652062756c6c277320657965'
    >>> XOR(a, b)
    '746865206b696420646f6e277420706c6179'
    """
    assert len(a) == len(b)
    x = int(a, 16)
    y = int(b, 16)
    xor = x ^ y
    return f"{xor:02x}"


if __name__ == "__main__":
    import doctest

    doctest.testmod()
