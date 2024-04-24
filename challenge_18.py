# Implement CTR, the stream cipher mode

# Quote from https://cryptopals.com/sets/3/challenges/18:
#
# "CTR mode encrypts a running counter, producing a 16 byte block of keystream,
#  which is XOR'd against the plaintext."
#
#  Block cipher algorithm:
#
#    C = Encrypt(concat(Nonce, Counter), Key) ^ P
#    P = Encrypt(concat(Nonce, Counter), Key) ^ C
#


from base64 import b64decode
from typing import Generator
from Crypto.Cipher import AES


def encrypt(plaintext: bytes, key: bytes, nonce: bytes, format: str = "") -> bytes:
    keystr = keystream(key, nonce, format)
    ciphertext = b"".join(
        xor(next(keystr), plaintext[i : i + 16]) for i in range(0, len(plaintext), 16)
    )
    return ciphertext


decrypt = encrypt


def keystream(
    key: bytes, nonce: bytes, format: str = ""
) -> Generator[bytes, None, None]:
    assert len(nonce) >= 8
    cipher = AES.new(key, AES.MODE_ECB)

    i = 0
    while True:
        x = nonce[:8] + int_to_bytes(i, 8)
        enc = cipher.encrypt(x)
        yield enc
        i += 1


def int_to_bytes(i: int, nbytes: int) -> bytes:
    res = bytearray(nbytes)
    k = 0
    while i:
        res[k] = i & 0xFF
        i >>= 8
        k += 1
    return bytes(res)


def xor(a: bytes, b: bytes) -> bytes:
    k = min(len(a), len(b))
    a += b"\x00" * (k - len(a))
    b += b"\x00" * (k - len(b))
    return bytes(x ^ y for (x, y) in zip(a, b))


def test():
    s = b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    ciphertext = b64decode(s)
    key = b"YELLOW SUBMARINE"
    nonce = b"\x00" * 8

    plaintext = decrypt(ciphertext, key, nonce)
    return plaintext


if __name__ == "__main__":
    print(test())
