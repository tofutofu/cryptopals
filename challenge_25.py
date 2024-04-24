# Break "random access read/write" AES CTR

# CTR block cipher:
#
#    C = AES(Concat(NONCE, COUNTER), KEY) ^ P
#    P = AES(Concat(NONCE, COUNTER), KEY) ^ C
#
# So, if for some block, we know both P and C, then for that block
# we know that AES(block) = P ^ C. So, then we can also recover the
# original P, given only the original C.
#
# This implies it's very dangerous to expose an edit-oracle or to
# support seekable + writable CTR ciphertext streams, since doing
# so makes it possible to break the encryption of the entire stream.


from base64 import b64decode
from Crypto.Cipher import AES

from challenge_09 import strip_pkcs7 as remove_padding
from challenge_18 import encrypt as ctr, keystream, xor

DATA_FILE = "./data/7.txt"  # AES-ECB encrypted with key "YELLOW SUBMARINE"

KEY = b"\x857\x93\x03z\x0c\x93e\\\xf1\xce\xa3\x8e\x83,2"
NONCE = b"'5&\xfc\x0f\xf9-\xa3\x95\x18K\x9e2\xdf\xec\x91"


def get_data() -> bytes:
    with open(DATA_FILE) as f:
        s = f.read()
    ciphertext = b64decode(s)
    cipher = AES.new(b"YELLOW SUBMARINE", AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return remove_padding(plaintext)


def edit(
    ciphertext: bytes,
    offset: int,
    newtext: bytes,
    key: bytes = KEY,
    nonce: bytes = NONCE,
) -> bytes:
    if not newtext:
        return ciphertext

    # the asserts are needed since we cannot overwrite partial blocks without
    # knowing what the original plaintext of those blocks was
    assert offset % 16 == 0
    assert len(newtext) % 16 == 0 or offset + len(newtext) > len(ciphertext)

    new_ciphertext = b""
    keystr = keystream(key, nonce)

    for i in range(0, max(len(ciphertext), offset + len(newtext)), 16):
        if i < offset:
            new_ciphertext += ciphertext[i : i + 16]
            next(keystr)
        elif i < offset + len(newtext):
            new_ciphertext += xor(next(keystr), newtext[offset - i : offset - i + 16])
        else:
            new_ciphertext += ciphertext[i:]
            break

    return new_ciphertext


def edit_oracle(ciphertext: bytes, offset: int, newtext: bytes) -> bytes:
    return edit(ciphertext, offset, newtext, KEY, NONCE)


def breakit(ciphertext: bytes) -> bytes:
    plaintext = b""

    for i in range(0, len(ciphertext), 16):
        newtext = b"\x00" * 16  # making them all 0, saves one xor call :)
        ct = edit_oracle(ciphertext, i, newtext)
        block = ct[i : i + 16]
        plaintext += xor(block, ciphertext[i : i + 16])

    return plaintext


def test():
    plaintext = get_data()
    ciphertext = ctr(plaintext, KEY, NONCE)
    recovered = breakit(ciphertext)
    assert recovered == plaintext


if __name__ == "__main__":
    test()
