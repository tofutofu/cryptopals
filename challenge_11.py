# ECB/CBC detection oracle.

# Write an `encryption_oracle` function that takes some text as input
# and uses a random, unknown key to either encrypt the input in ECB
# mode, half of the time or in CBC mode, half of the time. The mode is
# also randomly chosen. Then write a function that detects which
# block cipher mode this oracle was using each time.

# This problem gave me a hard time. I tried several approaches, but
# just couldn't find a way to always reliably distinguish ciphertexts
# generated in either ECB or CBC mode. And this problem was still
# supposed to be simple?!
#
# Then I read a blog post with some general notes about these
# challenges. The author wrote something like: "Problem 11 is also
# simple..." (wait, what?) "... since you control the input."
#
# So, finally it dawned on me that I had made the problem infinitely
# more difficult - and practically unsolvable - by misreading it. I
# had read it as:
#
#    Given some ciphertext that has been encoded either
#    in CBC or ECB mode, determine which mode was actually used.
#
# This turns out to be very hard - in general, with one rare, lucky,
# exceptional case. (If the unknown input happens to have a duplicate
# plaintext block of 16 bytes, then this also generates a duplicate
# block in the ciphertext.)  But... if you control the input text and
# are allowed to send your own input to the oracle, then the task is
# ridiculously simply, since you can just make this rare and lucky
# case happen.


from os import urandom
import random
from typing import Callable
from Crypto.Cipher import AES

from challenge_07 import remove_padding
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
