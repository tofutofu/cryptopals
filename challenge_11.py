# ECB/CBC detection oracle.

# Write an `encryption_oracle` function that takes some text as input
# and uses a random, unknown key to either encrypt the input in ECB
# mode, half of the time, or in CBC mode, half of the time. The mode is
# also randomly chosen. Then write a function that detects which
# block cipher mode this oracle was using each time.

# This problem gave me a hard time. I tried several approaches, but
# just couldn't find a way to always reliably distinguish ciphertexts
# generated in either ECB or CBC mode.
#
# Then I read a blog post with some general notes about the challenges.
# The author wrote something like: "Problem 11 is also simple..."
# (wait, what?) "... since you control the input."
#
# "Since you control the input". So, finally it dawned on me that I had
# made the problem infinitely more difficult - and practically unsolvable
# - by misreading it. I had read it as:
#
#    Given any ciphertext that has been AES encrypted
#    in either CBC or ECB mode, determine which mode was used.
#
# This turns out to be very hard and generally impossible to do - at
# least it's totally impossible to do this reliably with every ciphertext
# (not knowing the plaintext of course). There is only one rare exception:
# If the ciphertext contains a duplicate block, then it was very likely
# encrypted in ECB mode (even so, there is a greater than zero, though
# extremely small chance it was encrypted in CBC mode). But if the plaintext
# doesn't have any duplicate blocks, you'd never get this lucky break.
#
# The only way to distinguish CBC and ECB mode otherwise would be to
# use statistical methods. The difference between the two modes
# is that the previous cipherblock in CBC is xor'ed with the encrypted
# current block to generate the current cipherblock. This tends to create
# greater diffusion. So, you might now assume that the CBC ciphertext
# _should_ look "more random" than the ECB ciphertext (of the same input).
#
# But using various statistical tests from the NIST statistical test suite
# [A Statistical Test Suite for Random and Pseudorandom Number Generators]
# (https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=906762), I did not
# find a way to use this.
#
# For a Python implementation of those tests, see:
# https://github.com/stevenang/randomness_testsuite.
#
# For all practical purposes, based on any of the statisical tests, ECB and
# CBC appear equally random. I did not find a way to base a general, reliable
# detector on these tests. It appears that the lack of diffusion in ECB can
# only be noticed when there are duplicated blocks in the plaintext.
# (I only tested with natural language plaintexts of up to about 2000
# characters. Perhaps it's possible to distinguish ECB and CBC for longer
# input? Or do so with a greater than 50% chance of being correct?)
#
# But if you are allowed to manipulate the input, then, of course, the
# problem becomes trivial. Simply force that lucky break by sending a
# plaintext with duplicated blocks to the encryption oracle.


from os import urandom
import random
from typing import Callable
from Crypto.Cipher import AES

from challenge_09 import pkcs7


random.seed(20240401)


# This encryption oracle mimics probing a remote server.
# Even though the server is using a random key, random prefixes and
# suffixes and a randomly selected encryption mode,  you can determine
# each time which method the server is using by sending it a "carefully
# crafted" input string :)


def encryption_oracle() -> tuple[str, Callable]:
    if random.random() < 0.5:
        mode = "ECB"
    else:
        mode = "CBC"

    def oracle(plaintext: str | bytes) -> bytes:
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        key = urandom(16)
        prefix = urandom(random.randint(5, 10))
        suffix = urandom(random.randint(5, 10))

        plaintext = pkcs7(prefix + plaintext + suffix)

        if mode == "ECB":
            cipher = AES.new(key, AES.MODE_ECB)
        else:
            cipher = AES.new(key, AES.MODE_CBC, iv=urandom(16))

        return cipher.encrypt(plaintext)

    return mode, oracle


def detect(oracle: Callable) -> str:
    plaintext = "A" * 64
    ciphertext = oracle(plaintext)
    if ciphertext[32:48] == ciphertext[48:64]:
        return "ECB"
    return "CBC"


if __name__ == "__main__":
    for _ in range(10):
        mode, oracle = encryption_oracle()
        guessed_mode = detect(oracle)
        assert guessed_mode == mode
    print("OK")
