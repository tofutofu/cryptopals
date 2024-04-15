# Repeating-key XOR

from challenge_01 import bytes_to_hex, hex_to_bytes


def encrypt(plaintext: str | bytes, key: str | bytes, rt: type = str) -> str | bytes:
    r"""
    Encrypt the plaintext with repeated-key XOR.

    >>> s = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    >>> encrypt(s, "ICE")
    '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    >>> encrypt(s, "ICE", rt=bytes)
    b'\x0b67\'*+.cb,.ii*#i:*<c$ -b=c4<*&"c$\'\'e\'*(+/ C\ne.,e*1$3:e>+ \'c\x0ci+ (1e(c&0.\'(/'
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    if isinstance(key, str):
        key = key.encode("utf-8")
    n = len(key)

    res = [(byte ^ key[i % n]) for (i, byte) in enumerate(plaintext)]

    if rt is str:
        return bytes_to_hex(res)
    if rt is bytes:
        return bytes(res)
    raise ValueError(f"Invalid rt type ({rt}). Only str and bytes are supported.")


def decrypt(ciphertext: str | bytes, key: str | bytes, rt: type = str) -> str | bytes:
    r"""
    Decrypt the ciphertext with repeated-key XOR.

    This is really the same function as `encrypt`.

    >>> s = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    >>> expected = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    >>> assert decrypt(s, "ICE") == expected
    """
    if isinstance(ciphertext, str):
        ciphertext = hex_to_bytes(ciphertext)
    if isinstance(key, str):
        key = key.encode("utf-8")
    n = len(key)

    res = [(byte ^ key[i % n]) for (i, byte) in enumerate(ciphertext)]

    if rt is str:
        return "".join(chr(x) for x in res)
    return bytes(res)


if __name__ == "__main__":
    import doctest

    doctest.testmod()
