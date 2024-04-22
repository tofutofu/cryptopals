# Crack an MT19937 seed

# Given the first 32-bit output of an MT, how can you discover the initial seed?
#
# If the seed is a Unix timestamp, this is totally trivial:
# Just rewind the time backwards until you can regenerate the output.
#
# I guess the purpose of this exercise is just to show how ridiculously insecure
# it can be to use timestamps as seed values. It turns out that with this pure
# Python implementation it only takes about 20s per day of time difference between
# current time and the moment that MT was seeded.

import random
import time
from challenge_21 import MersenneTwister

mt = MersenneTwister()


def oracle():
    seed = int(time.time())
    mt.initialize(seed)
    time.sleep(random.randint(4, 10))
    return seed, mt.generate()


def crack(x):
    t = int(time.time())
    stop = t - 60
    y = None

    # simulate cracking the MT one day later
    t += 24 * 3600
    while t > stop:
        t -= 1
        mt.initialize(t)
        y = mt.generate()
        if y == x:
            end = time.time()
            return t

    return None


if __name__ == "__main__":
    print("Setting up PRNG ...")
    seed, x = oracle()

    print("Cracking time-based seed (one day later) ...")
    start = time.time()
    seed1 = crack(x)
    end = time.time()

    ok = "Correct" if seed1 == seed else "Incorrect"
    print(f"Found seed {seed1}: {ok}")
    print(f"Total time {end-start:.1f}")
