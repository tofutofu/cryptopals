# Implement CBC mode (Cipher Block Chaining).
#
# Implement AES-CBC using AES-ECB.

from base64 import b64decode
from Crypto.Cipher import AES

from challenge_07 import remove_padding
from challenge_09 import pkcs7


def enc_aes_ecb(plaintext: str | bytes, key: str | bytes) -> bytes:
    """
    Encrypt in AES-ECB mode.

    Note:
    - The key must be a 16-byte string.
    - The plaintext must be PKCS#7-padded since Cipher.encrypt
      does not add any padding.

    >>> from challenge_07 import decrypt as dec_aes_ecb
    >>> plaintext = "Giant Eels Under Northern Seas"
    >>> key = "YELLOW SUBMARINE"
    >>> dec_aes_ecb(enc_aes_ecb(plaintext, key), key)
    'Giant Eels Under Northern Seas'
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    if isinstance(key, str):
        key = key.encode("utf-8")

    if len(key) != 16:
        raise ValueError("Only 16-byte keys are supported in AES-ECB.")

    plaintext = pkcs7(plaintext, 16)

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)

    return ciphertext


def encrypt(plaintext: str | bytes, key: str | bytes, iv: bytes = b"") -> bytes:
    """
    AES encrypt in CBC mode.

    >>> plaintext = "Giant Eels Under Northern Seas"
    >>> key = "YELLOW SUBMARINE"
    >>> assert decrypt(encrypt(plaintext, key), key) == plaintext
    """
    if isinstance(key, str):
        key = key.encode("utf-8")
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    plaintext = pkcs7(plaintext, 16)

    if not iv:
        iv = b"\x00" * 16
    assert len(iv) == 16

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = b""

    prev_block = iv
    for i in range(0, len(plaintext), 16):
        text = XOR(prev_block, plaintext[i : i + 16])
        prev_block = cipher.encrypt(text)
        ciphertext += prev_block

    return ciphertext


def decrypt(ciphertext: bytes, key: str | bytes, iv: bytes = b"") -> str:
    """
    AES decrypt in CBC mode.
    """
    if isinstance(key, str):
        key = key.encode("utf-8")
    if not iv:
        iv = b"\x00" * 16
    assert len(iv) == 16

    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = b""

    prev_block = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i : i + 16]
        text = cipher.decrypt(block)
        plaintext += XOR(text, prev_block)
        prev_block = block

    plaintext = remove_padding(plaintext)

    return plaintext.decode("utf-8")


def XOR(a: bytes, b: bytes) -> bytes:
    return bytes((x ^ y) for (x, y) in zip(a, b))


if __name__ == "__main__":
    path = "data/10.txt"
    with open(path) as f:
        ciphertext = b64decode(f.read())

    print(f"File {path} decrypted:")
    print(decrypt(ciphertext, "YELLOW SUBMARINE"))
