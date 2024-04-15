from math import log2
from challenge_01 import hex_to_bytes


# Single-byte XOR cipher

# Decrypt a hex-encoded string that was encrypted by single-byte XOR.
#
# To decrypt this we can simply use a brute-force attack, trying out
# all 256 possible single-byte keys. Since we don't have time to
# check the candidate solutions, we score each solution by returning
# the candidate with the highest letter-unigram score, given a table
# of letter frequencies. This implicitly assumes that the plaintext
# was written in a particular language (English), since other languages
# would have other character frequencies.


# The following frequency table comes from Peter Norvig's article
# "English Letter Frequency Counts: Mayzner Revisited -- or ETAOIN SRHLDCU"
# (http://norvig.com/mayzner.html)
#
# The table is also roughly the same as the table in the Wikipedia entry for
# English letter frequencies: https://en.wikipedia.org/wiki/Letter_frequency
#
# It turns out that to decrypt single-byte-XOR a rough single-letter
# frequency score is enough.


FREQ = """
E 445.2 B  12.49%  E
T 330.5 B   9.28%  T
A 286.5 B   8.04%  A
O 272.3 B   7.64%  O
I 269.7 B   7.57%  I
N 257.8 B   7.23%  N
S 232.1 B   6.51%  S
R 223.8 B   6.28%  R
H 180.1 B   5.05%  H
L 145.0 B   4.07%  L
D 136.0 B   3.82%  D
C 119.2 B   3.34%  C
U  97.3 B   2.73%  U
M  89.5 B   2.51%  M
F  85.6 B   2.40%  F
P  76.1 B   2.14%  P
G  66.6 B   1.87%  G
W  59.7 B   1.68%  W
Y  59.3 B   1.66%  Y
B  52.9 B   1.48%  B
V  37.5 B   1.05%  V
K  19.3 B   0.54%  K
X   8.4 B   0.23%  X
J   5.7 B   0.16%  J
Q   4.3 B   0.12%  Q
Z   3.2 B   0.09%  Z
"""

LETTER_LOG_FREQUENCY = {}

for line in FREQ.split("\n"):
    tokens = line.strip().split()
    if not tokens:
        continue
    letter = tokens[0]
    log_count = log2(float(tokens[3].strip("%")) / 100.0)

    LETTER_LOG_FREQUENCY[letter] = log_count
    LETTER_LOG_FREQUENCY[letter.lower()] = log_count

# Adding some rough guesses for space and new-line. The guess for ascii space
# is based on the fact that most English words are about 6, 7 characters long.
# The value for new-line is probably quite a bit too high, but for the task at
# hand it's good enough.

LETTER_LOG_FREQUENCY[" "] = LETTER_LOG_FREQUENCY["N"]
LETTER_LOG_FREQUENCY["\n"] = LETTER_LOG_FREQUENCY["V"]

# Default for unknown letters

DEFAULT_LOG_FREQ = -12
assert DEFAULT_LOG_FREQ < LETTER_LOG_FREQUENCY["Z"]


def decrypt(ciphertext: str | bytes) -> tuple[float, str, str]:
    """
    Decrypt a hex-string ciphertext that was encrypted by single-byte XOR.

    >>> s = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    >>> decrypt(s)
    (-158.68701619884214, 'X', "Cooking MC's like a pound of bacon")
    """
    return max(score(ciphertext, byte) for byte in range(0, 256))


def score(ciphertext: str | bytes, byte: int):
    res = dec(ciphertext, byte)
    return (score_text(res), chr(byte), res)


def dec(ciphertext: str | bytes, byte: int) -> str:
    if isinstance(ciphertext, str):
        ciphertext = hex_to_bytes(ciphertext)
    if isinstance(byte, bytes):
        byte = ord(byte)
    assert 0 <= byte <= 0xFF
    return "".join(chr(x ^ byte) for x in ciphertext)


def score_text(s: str) -> float:
    return sum(LETTER_LOG_FREQUENCY.get(c, DEFAULT_LOG_FREQ) for c in s)


if __name__ == "__main__":
    import doctest

    doctest.testmod()
