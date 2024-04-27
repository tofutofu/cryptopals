# Implement and break HMAC-SHA1 with an artificial timing leak

import sys
import time
from typing import Callable
from challenge_28 import sha1


def hmac(
    key: bytes,
    msg: bytes,
    hasher: Callable = sha1,
    blocksize: int = 64,
    rt: type | None = None,
) -> bytes:
    """
    HMAC.

    Returns HMAC(key, msg, hash_function, blocksize).
    For SHA1 this is a 40-character hexdigest (20 bytes).

    >>> hmac(b"key", b"The quick brown fox jumps over the lazy dog")
    'de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9'
    """
    if len(key) > blocksize:
        key = hasher(key)
    key += b"\x00" * (blocksize - len(key))

    ipad = b"\x36" * blocksize
    opad = b"\x5c" * blocksize

    inner = hasher(xor(key, ipad) + msg, rt=bytes)
    outer = xor(key, opad)

    return hasher(outer + inner, rt=rt)


def xor(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for (x, y) in zip(a, b)])


# Server-side

KEY = b"012345ABCDEF"


def verify(msg: bytes, signature: str, key: bytes = KEY) -> bool:
    return hmac(key, msg) == signature


def insecure_compare(a: str | bytes, b: str | bytes, ms_delay: int = 50) -> bool:
    assert ms_delay >= 0
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False
        time.sleep(ms_delay / 1000.0)
    return True


def insecure_verify(
    msg: bytes, signature: str, key: bytes = KEY, ms_delay: int = 50
) -> bool:
    return insecure_compare(hmac(key, msg), signature, ms_delay=ms_delay)


# Client-side

# With 10 ms delay, the simple algorithm starts making mistakes
# after about 6 characters.
# But by just repeating the timing step once, we get better values.
# This breaks again, however, for ms_delay=5 (starts making mistakes
# after solving about half).
#
# The funny thing is that it only breaks after a few steps.
# So, one strategy is to gradually increase the nr of measurements.
#
# For ms_delay = 1 this still makes mistakes.


def find_mac(path: str = "challenge_31.py", ms_delay: int = 50):
    def get_repeats(i: int):
        if ms_delay >= 40:
            return 1
        if ms_delay >= 20:
            if i < 20:
                return 1
            return 2
        if ms_delay >= 10:
            return 2
        if ms_delay >= 5:
            if i < 20:
                return 2
            return 3
        # ms_delay < 5
        if i < 20:
            return 4
        if i < 30:
            return 5
        return 6

    with open(path, "rb") as f:
        msg = f.read()

    print(f"Testing ms_delay {ms_delay} ms")
    target = hmac(KEY, msg)
    print("Actual MAC:", target)

    mac = ["0" for _ in range(40)]
    sys.stdout.write("Found:      ")
    sys.stdout.flush()

    for i in range(40):
        max_time = 0.0
        best = "?"
        repeats = get_repeats(i)
        for c in "0123456789abcdef":
            mac[i] = c
            signature = "".join(mac)
            dt = 0.0
            for r in range(repeats):
                start = time.time()
                _ = insecure_verify(msg, signature, KEY, ms_delay=ms_delay)
                end = time.time()
                dt += end - start
            if dt > max_time:
                max_time = dt
                best = c
        mac[i] = best
        sys.stdout.write(best)
        sys.stdout.flush()
    sys.stdout.write("\n")

    signature = "".join(mac)
    print("Found ", signature)
    print("Actual", target)
    print("Correct", signature == target)


if __name__ == "__main__":
    ms_delay = int(sys.argv[1]) if len(sys.argv) == 2 else 50
    find_mac(ms_delay=ms_delay)
