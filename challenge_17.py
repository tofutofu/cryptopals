# The CBC padding oracle

# An excellent explanation can be found at
# https://research.nccgroup.com/2021/02/17/cryptopals-exploiting-cbc-padding-oracles
#
# The Wikipedia entry about Padding Oracles is awkardly formulated and makes
# everything a bit harder to understand than it really is.


from os import urandom
from base64 import b64decode
import random

from Crypto.Cipher import AES

from challenge_01 import bytes_to_hex
from challenge_09 import pkcs7, strip_pkcs7
from challenge_15 import validate_pkcs7


random.seed(20240401)

# Random but fixed key

KEY = b"\xa1\x89\xf1/\xd4\x163b\xa5\xd6\x1f \xdc\xe8z\xda"


DATA = b"""
MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
""".strip().split(
    b"\n"
)


def encrypt() -> bytes:
    """Encrypt one of the data lines.

    Returns iv + ciphertext concatenated.
    """
    cipher = AES.new(KEY, AES.MODE_CBC)
    plaintext = pkcs7(b64decode(random.choice(DATA)))
    print(f"Encrypting: {plaintext}")
    ciphertext = cipher.encrypt(plaintext)
    return cipher.iv + ciphertext  # type: ignore


def oracle(s: bytes, key: bytes = KEY) -> bool:
    """
    Takes as input a byte string (iv + ciphertext).

    Returns True/False if the decrypted plaintext has valid/invalid padding.
    """
    iv, ciphertext = s[:16], s[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = cipher.decrypt(s)
    try:
        validate_pkcs7(plaintext)
        return True
    except:
        return False


# TODO

    
def pp(prefix: str, s: bytes | bytearray):
    print(prefix, bytes_to_hex(s, 4, -1))



if __name__ == "__main__":
    pass
