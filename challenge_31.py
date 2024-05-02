# Implement and break HMAC-SHA1 with an artificial timing leak

import sys
import time
from typing import Callable
import numpy as np

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
    #
    # insecure because it's using an early exit which allows the timing attack
    #
    # this can trivially be made secure by always looking at _all_ of a and b
    #
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
# If the delay is short then the variance in timings is greater, so
# after a while it will start making mistakes. It may be best to
# measure the stddev in each round and use that for determininig the
# number of repeats to use in the next round. It's kind of hard to fine-tune
# this so that it works for ms_delay < 5. The code below works for ms_delay == 5
# but still makes mistakes for smaller delays.
#
# One way to deal with this, is to let the search run to the end, then
# check, and backtrack. I got tired of the problem so didn't implement this.


def find_mac(path: str = "challenge_31.py", ms_delay: int = 50, max_probes: int = 10):
    with open(path, "rb") as f:
        msg = f.read()

    print(f"Testing ms_delay {ms_delay} ms")
    target = hmac(KEY, msg)
    print("Actual MAC:", target)

    mac = ["0" for _ in range(40)]
    sys.stdout.write("Found:      ")
    sys.stdout.flush()

    best = "?"
    dt_offset = 0.0

    for i in range(40):
        for nn in range(max_probes):
            timings = np.zeros(16)
            for j, c in enumerate("0123456789abcdef"):
                mac[i] = c
                signature = "".join(mac)
                start = time.time()
                _ = insecure_verify(msg, signature, KEY, ms_delay=ms_delay)
                timings[j] = time.time() - start

            # normalize
            timings = (timings - timings.mean()) / timings.std()

            # find three best indices
            k3, k2, k1 = timings.argpartition(-3)[-3:]
            best = "0123456789abcdef"[k1]

            m1 = timings[k1]

            # thresholding
            if m1 > 3.6:
                break

            m2 = timings[k2]
            m3 = timings[k3]

            timings.sort()
            diffs = timings[1:] - timings[:-1]
            diffs_avg = diffs.mean()
            diffs_std = diffs.std()

            d1 = (m1 - m2 - diffs_avg) / diffs_std
            d2 = (m2 - m3 - diffs_avg) / diffs_std

            if d1 > 2 * d2:
                break

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
