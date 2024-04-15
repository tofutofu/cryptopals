# Decrypt AES in ECB mode

from base64 import b64decode
from Crypto.Cipher import AES


def decrypt(ciphertext: bytes, key: str | bytes) -> str:
    if isinstance(key, str):
        key = key.encode("utf-8")

    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext).decode("utf-8")

    return plaintext


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
