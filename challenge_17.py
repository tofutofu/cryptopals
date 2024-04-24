# The CBC padding oracle

# An oracle that just returns information whether or not the padding is valid
# when decrypting some CBC-encrypted ciphertext, is sufficient to fully decrypt that
# ciphertext.

# An very clear, well-written explanation can be found at
# https://research.nccgroup.com/2021/02/17/cryptopals-exploiting-cbc-padding-oracles
#
# The Wikipedia entry about Padding Oracles is rather hard to follow unless you already
# understand the algorithm.


from base64 import b64decode
import random

from Crypto.Cipher import AES

from challenge_01 import bytes_to_hex
from challenge_09 import pkcs7, strip_pkcs7 as remove_padding
from challenge_15 import validate_pkcs7


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
    print(f"Encrypting: {remove_padding(plaintext)!r}")
    ciphertext = cipher.encrypt(plaintext)
    return cipher.iv + ciphertext  # type: ignore


def padding_oracle(s: bytes, key: bytes = KEY) -> bool:
    """
    Takes as input a byte string (iv + ciphertext).

    Returns True/False if the decrypted plaintext has valid/invalid padding.
    """
    iv, ciphertext = s[:16], s[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = cipher.decrypt(ciphertext)
    try:
        validate_pkcs7(plaintext)
        return True
    except ValueError:
        return False


# Generally, we have V ^ D(C) = P   (C1 ^ D(C2) = P)
# We start with Z = V (but we could start with an arbitrary Z).
# We manipulate Z, so that Z ^ D(C) = ...\x01  (at byte position 15).
# When the padding oracle returns True, we have Z ^ D(C) == 1
# -> D(C) = Z ^ 1
# -> P = Z ^ 1 ^ V
#
# In the next round we want Z ^ D(C) = ...\x02\x02
# -> Z = D(C) ^ 2 = Z ^ 1 ^ 2


def attack_single_block(iv: bytes, ciphertext: bytes) -> bytes:
    plaintext = bytearray([0] * 16)
    ziv = bytearray(iv)

    for i in range(15, -1, -1):
        padding = bytearray([16 - i] * 16)
        ziv = xor(padding, ziv)

        for byte in range(256):
            ziv[i] = byte
            if padding_oracle(ziv + ciphertext):
                if i == 15:  # double-check
                    ziv[14] ^= 1
                    if not padding_oracle(ziv + ciphertext):
                        continue

                ziv = xor(ziv, padding)
                plaintext = xor(ziv, iv)
                break

    return bytes(plaintext)


def attack(ciphertext: bytes) -> bytes:
    plaintext = bytes(b"")
    for i in range(0, len(ciphertext) - 16, 16):
        iv, ct = ciphertext[i : i + 16], ciphertext[i + 16 : i + 32]
        plaintext += attack_single_block(iv, ct)
    return remove_padding(plaintext)


def xor(a, b):
    return bytearray(x ^ y for (x, y) in zip(a, b))


def pp(prefix: str, s: bytes | bytearray):
    print(prefix, bytes_to_hex(s, 4, -1))


def test():
    ciphertext = encrypt()
    print(f"Decryption: {attack(ciphertext)!r}")


if __name__ == "__main__":
    test()
