# Decrypt AES in ECB mode

from base64 import b64decode
from Crypto.Cipher import AES

# Note:
# - Cipher.encrypt does not add any padding to the plaintext before encryption
# - Cipher.decrypt does not remove any padding from the returned plaintext


def decrypt(ciphertext: bytes, key: str | bytes) -> str:
    if isinstance(key, str):
        key = key.encode("utf-8")

    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    plaintext = remove_padding(decrypted).decode("utf-8")

    return plaintext


def remove_padding(s: bytes, validate: bool = True) -> bytes:
    if not s:
        if validate:
            raise ValueError("Empty input")
        return b""
    pad_byte = int(s[-1])
    if validate:
        padding = bytes([pad_byte] * pad_byte)
        if not s.endswith(padding):
            raise ValueError("Invalid padding")
    return s[:-pad_byte]


def decrypt_file(path: str = "data/7.txt", key: str = "YELLOW SUBMARINE") -> str:
    """
    Decrypt a base64-encoded file that was encrypted with AES in ECB mode.

    >>> s = decrypt_file()
    >>> assert s.startswith("I'm back and I'm ringin' the bell")
    """
    with open(path) as f:
        ciphertext = b64decode(f.read())

    return decrypt(ciphertext, key)


if __name__ == "__main__":
    import doctest

    doctest.testmod()
