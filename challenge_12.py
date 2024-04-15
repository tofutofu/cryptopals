# Byte-at-a-time ECB decryption (Simple)

from base64 import b64decode
from os import urandom
import random
from typing import Callable
from Crypto.Cipher import AES

from challenge_09 import pkcs7


random.seed(20240401)

DEBUG = False

MYSTERY_TEXT = """
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
"""


def encryption_oracle(key: bytes = b"") -> tuple[str, Callable]:
    key = key or urandom(16)
    secret = b64decode(MYSTERY_TEXT.strip())

    def oracle(plaintext: str | bytes) -> bytes:
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        plaintext = pkcs7(plaintext + secret)
        cipher = AES.new(key, AES.MODE_ECB)

        return cipher.encrypt(plaintext)

    return "ECB", oracle


def uncover_secret():
    _, oracle = encryption_oracle()

    blocksize = uncover_blocksize(oracle)
    if blocksize is None:
        raise NotImplementedError(
            "Failed to determine block-size. Oracle is not using AES-ECB."
        )

    secret_length = uncover_target_length(oracle, blocksize)

    secret = ""
    step = 1
    while True:
        if len(secret) >= secret_length:
            break
        next_letter = probe(oracle, secret, blocksize)
        if not next_letter:
            break
        secret += next_letter
        if DEBUG:
            print(f"[{step}] {secret!r}")
        step += 1
    return secret


def uncover_blocksize(oracle: Callable) -> int | None:
    for blocksize in range(8, 128):
        plaintext = "A" * blocksize * 2
        ciphertext = oracle(plaintext)
        if ciphertext[0:blocksize] == ciphertext[blocksize : 2 * blocksize]:
            return blocksize
    return None


def uncover_target_length(oracle: Callable, blocksize: int) -> int:
    n = len(oracle(""))
    res = [len(oracle(" " * k)) for k in range(0, blocksize)]
    if len(set(res)) == len(res):
        return n
    m = n
    for length in res:
        if length > n:
            break
        m -= 1
    return m


def probe(oracle: Callable, found: str, blocksize: int) -> str:
    # make a probe that is able to contain everything found so far
    # and then still has at least one free cell
    nblocks = 1 + (len(found) // blocksize)

    # point j to the last block of the probe
    j = blocksize * (nblocks - 1)

    k = nblocks * blocksize - len(found) - 1

    prefix = [ord("A")] * k
    suffix = [ord(c) for c in found]

    # let the oracle fill in the last letter of block j with the next,
    # not-yet-discovered letter of the secret.
    target = oracle(bytes(prefix))

    # run a brute-force attack to see which byte matches
    for letter in range(256):
        ciphertext = oracle(bytes(prefix + suffix + [letter]))
        if ciphertext[j : j + blocksize] == target[j : j + blocksize]:
            return chr(letter)

    return ""


if __name__ == "__main__":
    secret = uncover_secret()
    print()
    print("The uncovered text is:")
    print()
    print(secret)
