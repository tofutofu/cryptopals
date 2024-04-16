# CBC bitflipping attacks

# Without knowledge of the key, modify the ciphertext, so that it
# will decrypt to contain the string ';admin=true'.

# From Wikipedia:
#
# Note that a one-bit change to the ciphertext causes complete corruption of
# the corresponding block of plaintext, and inverts the corresponding bit in
# the following block of plaintext, but the rest of the blocks remain intact.
# This peculiarity is exploited in different padding oracle attacks, such as
# POODLE.
#

# A one-bit change in some ciphertext block, will lead to a
# completely scrambled result in the corresponding decrypted block,
# and to only one-bit-error in the next decrypted block.

# So we start with
#
# |xxxxxxxxxxxxxxxx|x%3Badmin%3Dtrue|
#  0123456789012345 0123456789012345
#
# and want to get for instance
#
# |xxxxxxxxxxxxxxxx|xxxxx;admin=true|
#  0123456789012345 0123456789012345

# By manipulating bytes in the preceding cipher text block, the decryption
# of _that_ block will be scrambled (and we don't care about that), but
# corresponding bytes in the next block will change in the same way.


from os import urandom
import random
from urllib.parse import quote, unquote

from Crypto.Cipher import AES

from challenge_01 import bytes_to_hex
from challenge_09 import pkcs7, strip_pkcs7
from challenge_15 import validate_pkcs7


random.seed(20240401)

# Random but fixed key

KEY = b"\xa1\x89\xf1/\xd4\x163b\xa5\xd6\x1f \xdc\xe8z\xda"


def prepare_payload(s: str) -> str:
    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
    return prefix + quote(s) + suffix


def encrypt_payload(s: str, key: bytes = KEY) -> tuple[bytes, bytes]:
    plaintext = pkcs7(prepare_payload(s).encode("utf-8"))
    iv = urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(plaintext), iv


def decrypt_payload(
    s: bytes, key: bytes = KEY, iv: bytes = b"", rt=bytes
) -> str | bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=iv or urandom(16))
    plaintext = cipher.decrypt(s)
    if validate_pkcs7(plaintext):
        plaintext = strip_pkcs7(plaintext)
    if rt is str:
        return safe_decode(plaintext)
    return plaintext


def safe_decode(s: bytes):
    filler = "?" * 16
    prefix = ""
    for i in range(0, len(s), 16):
        try:
            return prefix + s[i:].decode("utf-8")
        except UnicodeDecodeError:
            prefix += filler
    raise ValueError(f"Failed to decode: {s!r}")


def detect_admin(s: bytes, key: bytes = KEY, iv: bytes = b"") -> bool:
    plaintext = decrypt_payload(s, key, iv)
    return ";admin=true;" in plaintext


def pp(s: bytes):  # pretty printer
    print(bytes_to_hex(s, 8, 4))


def flipbit(
    s: bytes | list[int], block: int, byte: int, bit: int, blocksize: int = 16
) -> bytes:
    """
    Flip one bit in the input bytes string.

    The call `flipbit(s, -1, -1, 0)` flips bit 0 (least-significant bit) in
    the last byte of the last block.
    """
    s = list(s)
    assert -8 <= bit < 8
    assert -blocksize <= byte < blocksize
    bit = bit % 8
    byte = byte % blocksize

    s[block * blocksize + byte] ^= 1 << bit

    return bytes(s)


def malicious_payload():
    ciphertext, iv = encrypt_payload("x" * 16 + "x;admin=true")
    cipherbytes = bytearray(ciphertext)

    plaintext = decrypt_payload(ciphertext, iv=iv)

    assert (
        plaintext
        == b"comment1=cooking%20MCs;userdata=xxxxxxxxxxxxxxxxx%3Badmin%3Dtrue;comment2=%20like%20a%20pound%20of%20bacon"
    )

    original = b"%3Badmin%3D"
    modified = b"xxxx;admin="

    offset = plaintext.find(original)

    for i, (a, b) in enumerate(zip(original, modified)):
        cipherbytes[offset + i - 16] ^= a ^ b

    return bytes(cipherbytes), iv


if __name__ == "__main__":
    payload, iv = malicious_payload()
    plaintext = decrypt_payload(payload, iv=iv)

    print("Plaintext:")
    print(plaintext)
    print()

    if plaintext.find(b";admin=true;"):  # type: ignore
        print("Success! Plaintext contains ';admin=true;'.")
    else:
        print("Failure! Plaintext does not contain ';admin=true;'.")
