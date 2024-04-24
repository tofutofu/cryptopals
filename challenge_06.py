# Break repeating-key XOR ("Vigenere")

from base64 import b64decode
import sys

from challenge_03 import decrypt as decrypt_single_byte_XOR
from challenge_03 import score_text
from challenge_05 import decrypt as decrypt_repeated_key_XOR


DEBUG = False


def decrypt(
    path: str = "data/6.txt", max_key_length: int = 41
) -> tuple[float, str, str]:
    r"""
    Decrypt a file that was encrypted with repeated-key XOR.
    Returns (log_score, key, plaintext) of the best candidate decryption.

    >>> score, key, plaintext = decrypt("data/6.txt")
    >>> assert score == -13375.38464213255
    >>> assert len(key) == 29
    >>> assert plaintext.startswith("I'm back")
    """

    #
    # b64decode the input file
    #
    with open(path) as f:
        ciphertext = b64decode(f.read())

    #
    # get sorted list of most likely key lengths (from 2 up to 41)
    #
    key_lengths = get_sorted_key_lengths(ciphertext, 2, max_key_length)

    #
    # run single-key XOR decryption on the transposed text blocks
    #

    masterkeys = []

    for i, key_length in enumerate(key_lengths[:10]):
        masterkey = ""
        plaintext = ""
        blocks = get_transposed_blocks(ciphertext, key_length)
        for block in blocks:
            _, key, transposed_txt = decrypt_single_byte_XOR(block)
            masterkey += key
            plaintext += transposed_txt[0]  # only used for debugging
        masterkeys.append(masterkey)

        if DEBUG:
            if " the " in plaintext:
                tag = "***** "
            else:
                tag = ""
            print(f"{tag}[{i}] Key: {masterkey!r}", file=sys.stderr)
            print(f"{tag}[{i}] Plaintext: {plaintext!r} ...", file=sys.stderr)

    #
    # Use the candidate keys to try to decrypt the original ciphertext.
    # Return the (score, key, plaintext) with the highest letter-frequency score.
    #

    scored = []

    for key in masterkeys:
        plaintext = decrypt_repeated_key_XOR(ciphertext, key)  # type: ignore
        scored.append((score_text(plaintext), key, plaintext))

    res = sorted(scored)[-1]

    if DEBUG:
        print(file=sys.stderr)
        print(f"Score: {res[0]:.3f}", file=sys.stderr)
        print(f"Key: {res[1]!r}", file=sys.stderr)
        print(f"Plaintext: {res[2][:45]!r}...", file=sys.stderr)

    return res


def get_sorted_key_lengths(
    ciphertext: bytes, min_length: int, max_length: int
) -> list[int]:
    res = []
    for key_length in range(min_length, max_length + 1):
        block1 = ciphertext[0:key_length]
        block2 = ciphertext[key_length : 2 * key_length]
        block3 = ciphertext[2 * key_length : 3 * key_length]
        block4 = ciphertext[3 * key_length : 4 * key_length]
        dist = (
            hamming_distance(block1, block2) + hamming_distance(block3, block4)
        ) / key_length
        res.append((dist, key_length))

    res.sort()

    if DEBUG:
        print("Sorted key_lengths", file=sys.stderr)
        for i, (dist, key_length) in enumerate(res):
            print(
                f"[{i}] key_length={key_length:2}  distance={dist:.3f}", file=sys.stderr
            )
        print(file=sys.stderr)

    return [key_length for (_, key_length) in res]


def hamming_distance(a: bytes | list[int], b: bytes | list[int]) -> int:
    """
    >>> a = b"this is a test"
    >>> b = b"wokka wokka!!!"
    >>> hamming_distance(a, b)
    37
    >>> a = list(map(ord, "this is a test"))
    >>> b = list(map(ord, "wokka wokka!!!"))
    >>> hamming_distance(a, b)
    37
    """
    return sum((x ^ y).bit_count() for (x, y) in zip(a, b))


def get_transposed_blocks(ciphertext: bytes, key_length: int):
    blocks: list[list[int]] = [[] for _ in range(key_length)]

    for i, byte in enumerate(ciphertext):
        blocks[i % key_length].append(byte)

    return blocks


if __name__ == "__main__":
    import doctest

    if "-x" in sys.argv:
        sys.argv.remove("-x")
        DEBUG = True

    doctest.testmod()
