# Detect AES in ECB mode

# You are given a bunch of strings (hexstrings). One of them has been encrypted with AES in ECB mode.
# Detect which one.
#
# Hint: ECB mode is stateless and deterministic. The same 16-byte plaintext block
# always generates the same 16-byte ciphertext block.
#
# Approach: If there is one string with a duplicate block, then that's our best candidate.
#
# If no strings have duplicates, can we then find the target string? Would it make sense
# to apply a distance metric on the ciphertexts, comparing ciphertext blocks?
# It took me a while to realize that that doesn't make _much_ sense. It only makes sense
# as a method to find duplicates...
#
# Does it make sense to use the total count of duplicates found in a line as as score
# to compare lines? Not really... If multiple string have duplicate blocks, it's not clear
# why a string with more duplicates would be more likely to be ECB encrypted than a string
# with fewer duplicates. There is no general reason to use this count as criterion.
# It might actually be _less_ likely to find _more_ duplicate 16-byte blocks in a natural
# language plaintext. And for relatively short string, I would assume that it is in fact
# less likely.

from typing import Sequence


def detect_ECB(
    lines: Sequence[str | bytes], blocksize: int = 16
) -> tuple[int, str | bytes]:
    duplicated = []
    for i, line in enumerate(lines):
        blocks = to_blocks(line, blocksize=blocksize)
        if has_duplicates(blocks):
            duplicated.append((i, line))
    if not duplicated:
        return (-1, "")
    if len(duplicated) > 1:
        print(
            f"Warning: Found {len(duplicated)} strings with duplicated blocks. "
            "Returning only the first string."
        )
    return duplicated[0]


def to_blocks(line: str | bytes, blocksize: int = 16) -> list[str | bytes]:
    return [line[i : i + blocksize] for i in range(0, len(line), blocksize)]


def has_duplicates(blocks: list) -> bool:
    return len(set(blocks)) < len(blocks)


if __name__ == "__main__":
    with open("data/8.txt") as f:
        lines = f.readlines()
    lines = [line.strip() for line in lines if line.strip()]

    lineno, line = detect_ECB(lines, blocksize=32)
    if lineno == -1:
        print("Found no strings containing duplicated 16-byte blocks")
    else:
        print(f"The line that most likely used AES-ECB is line {lineno}.")
        print(f"Ciphertext: {line!r}")
