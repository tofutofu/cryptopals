# Byte-at-a-time ECB decryption

# Similar to challenge_12, but now with an added random-length prefix.
#
# The random prefix is appended to every plaintext.
#
# Initially, I misread this as: A _different_ random-length string
# is prepended to every plaintext. It turns out to be extremely hard
# to then find a solution. In fact, I wasn't able to implement one.
#
# If a new random-length string is prepended each time, you can figure out
# how many possible lengths (modulo 16) this string can have. But the only
# way to use the oracle to discover the target text, is if you can align
# the probe texts ('AAA....AX', 'AAA...AXY', etc) with blocks. If every
# probe starts with a different length prefix, then the only way to do so
# -- the only way I could think of --, is to just keep trying, using
# probes with different lengths of 'A...A', and then hoping to find two
# identical blocks. With enough random tries, you should eventually find
# a duplicate. But this still means that for every letter to be discovered,
# you'd need on average 16 * 16 * 256 = 65K attempts.


from base64 import b64decode
from os import urandom
import random
from typing import Callable
from Crypto.Cipher import AES

from challenge_01 import bytes_to_hex
from challenge_09 import pkcs7


random.seed(20240401)

DEBUG = False

MYSTERY_TEXT = """
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
"""


def encryption_oracle(key: bytes = b"", prefix: bytes = b"") -> tuple[str, Callable]:
    key = key or urandom(16)
    prefix = prefix or urandom(33)
    secret = b64decode(MYSTERY_TEXT.strip())

    def oracle(plaintext: str | bytes) -> bytes:
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        plaintext = pkcs7(prefix + plaintext + secret)
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
    print(f"Blocksize is {blocksize}")

    prefix_length, secret_length_range = uncover_prefix_and_target_length(
        oracle, blocksize
    )
    print(f"Prefix length is {prefix_length}")
    print(f"Secret length is in range {secret_length_range}")

    secret = ""
    step = 1
    while True:
        next_letter = probe(oracle, secret, blocksize, prefix_length)
        if not next_letter:
            break
        secret += next_letter
        if DEBUG:
            print(f"[{step}] {secret!r}")
        step += 1

    return secret


def uncover_blocksize(oracle: Callable) -> int | None:
    for blocksize in range(8, 128):
        plaintext = "A" * blocksize * 3
        ciphertext = oracle(plaintext)
        for j in range(0, len(ciphertext), blocksize):
            if (
                ciphertext[j : j + blocksize]
                == ciphertext[j + blocksize : j + 2 * blocksize]
            ):
                return blocksize
    return None


def uncover_prefix_and_target_length(
    oracle: Callable, blocksize: int
) -> tuple[int, tuple[int, int]]:
    prefix_length = -1
    secret_length_range = (-1, -1)

    n = len(oracle(""))

    probe = bytes(b"A" * 32)

    for k in range(16):
        c = oracle(probe)
        i = find_duplicate_blocks(c)

        if i >= 0:
            prefix_length = i - k
            secret_length_range = (n - prefix_length - 16, n - prefix_length)

            break
        probe += b"A"

    # verify that we don't happen to have a "random" prefix that
    # ends with a series of 'A...A' since that would invalidate the discovered lengths!

    if prefix_length % 16 == 0:
        extra = 0
    else:
        extra = 16 - (prefix_length % 16)

    c = oracle(bytes(b"X" * (32 + extra)))
    i = find_duplicate_blocks(c)

    if i != prefix_length + k:
        raise ValueError(
            f"The 'random' prefix already happens to contain a duplicate block at {i}!"
        )

    return prefix_length, secret_length_range


def find_duplicate_blocks(s: bytes | bytearray) -> int:
    for i in range(16, len(s), 16):
        if s[i - 16 : i] == s[i : i + 16]:
            return i - 16
    return -1


def probe(
    oracle: Callable, found: str, blocksize: int, random_prefix_length: int
) -> str:
    if random_prefix_length % 16 == 0:
        extra = 0
    else:
        extra = 16 - (random_prefix_length % 16)

    # make a probe that is able to contain everything found so far
    nblocks = 1 + (len(found) // blocksize)
    k = nblocks * blocksize - len(found) - 1

    prefix = [ord("A")] * (k + extra)
    suffix = [ord(c) for c in found]

    # point j to the index of the target block that should be checked (last block in probes)
    # (due to the random prefix there are earlier duplicates that should be ignored!)
    j = random_prefix_length + extra + k + len(found) + 1 - 16

    # let the oracle fill in the last letter of the prefix block
    # with the next, not-yet-discovered letter of the secret
    target = oracle(bytes(prefix))

    # run a brute-force attack to see which byte matches the hidden letter
    for letter in range(256):
        ciphertext = oracle(bytes(prefix + suffix + [letter]))
        if ciphertext[j : j + blocksize] == target[j : j + blocksize]:
            return chr(letter)

    return ""


def pp(s: bytes | bytearray):
    print(bytes_to_hex(s, 8, 2))


if __name__ == "__main__":
    secret = uncover_secret()
    print()
    print("The uncovered text is:")
    print()
    print(secret)
