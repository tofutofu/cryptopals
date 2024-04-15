# Detect single-character XOR.
#
# Given about 300 60-character strings, detect which string was encrypted by single-character XOR.
# The input strings are hex-encoded strings.
#
# It turns out that a brute-force attack is again good enough. We can use the letter-frequency
# scoring method of challenge_03 to decrypt the strings, and then select the candidate decryption
# that has the highest score. More generally, if the input could contain more than one encrypted
# string, we could reject all decrypted candidates that are "too dissimilar" to English text.

from challenge_03 import decrypt


def detect_single_byte_XOR(path: str = "data/4.txt") -> tuple[float, str, str]:
    """
    Detect which line in the input file is mostly likely XOR-encrypted.
    Returns a tuple (log_score, key, plaintext).

    >>> detect_single_byte_XOR()
    (-133.2429504586544, '5', 'Now that the party is jumping\n')
    """
    with open(path) as f:
        lines = f.readlines()
        lines = [line.strip() for line in lines if line.strip()]

    best_candidate = max(decrypt(line) for line in lines)
    return best_candidate


def analyze(path: str = "data/4.txt"):
    """
    Show the main statistics on the scores.

    This shows that the best candidate is indeed much better with
    a score of more than 6 stdevs higher than the mean or median
    scores.
    """
    import numpy as np

    with open(path) as f:
        lines = f.readlines()
        lines = [line.strip() for line in lines if line.strip()]

    candidates = [decrypt(line) for line in lines]
    min_candidate = min(candidates)
    max_candidate = max(candidates)

    scores = [x[0] for x in candidates]

    mean = np.mean(scores)
    median = np.median(scores)
    std = np.std(scores)

    print(f"Max score:    {max_candidate[0]:.3f} {max_candidate[-1]!r}")
    print(f"Min score:    {min_candidate[0]:.3f} {min_candidate[-1]!r}")
    print(f"Mean score:   {mean:.3f}")
    print(f"Median score: {median:.3f}")
    print(f"Stdev:        {std:8.3f}")


if __name__ == "__main__":
    import doctest

    doctest.testmod()
