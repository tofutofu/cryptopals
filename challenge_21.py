import numpy as np

# Implement the MT19937 Mersenne Twister PRNG

# MT19937 - uses a 32-bit word length. Gets its name from Mersenne prime 2**19937 - 1.
# It generates pseudo-random numbers in the range [0, 2**32 - 1].
#
# Wikipedia gives a pretty clear presentation of the algorithm.
#
# The Python implementation in CPython follows the algorithm. The seeding
# has been made a bit more involved but follows the description in the
# following reference:
#
# "Cryptographic Mersenne Twister and Fubuki Stream/Block Cipher",
# Makoto Matsumoto, Takuji Nishimura, Mariko Hagita, and Mutsuo Saito (2005)
# (https://eprint.iacr.org/2005/165.pdf)
#
# Note: "The constant 19650218 is the birthday of one of the authors, chosen
# without reason. The other constant 1812433253 is a multiplier for a linear
# congruential generator, here chosen without reason."
#
# My implementation is based on the Wikipedia description, and I confess to
# also consulting a Chat GPT 3.5 implementation (which turned out to be pretty
# decent). I then also compared the basic functions to the CPython core code
# in Modules/_randommodule.c. To make testing and debugging easier I re-implemented
# the seeding code from CPython (which follows the reference) plus the getstate and
# setstate functions.
#
# The CPython random module does not cache the `seed` value. I do, just for convenience.
#

#
# Constants and coefficients
#
_n = 624
_m = 397  # prime
_u = 11
_s = 7
_t = 15
_l = 18
_a = 0x9908B0DF  # 15 bits are set
_b = 0x9D2C5680  # 13 bits
_c = 0xEFC60000  # 11 bits
_d = 0xFFFFFFFF
_f = 1812433253  # 14 bits

UPPER_MASK = 0x8000_0000
LOWER_MASK = 0x7FFF_FFFF

VERSION = 3


def u32(x: int):
    return x & 0xFFFF_FFFF


class MersenneTwister:
    def __init__(self, seed: int | None = None):
        if seed is None:
            seed = 0
        assert 0 <= seed <= 0xFFFF_FFFF
        self.seed = seed
        self.state = [0 for _ in range(_n)]
        self.index = _n
        self.init_by_u32(seed)

    def initialize(self, seed):
        self.state[0] = seed
        for i in range(1, _n):
            self.state[i] = u32(
                _f * (self.state[i - 1] ^ (self.state[i - 1] >> 30)) + i
            )
        self.index = _n

    def generate(self) -> int:
        """
        Returns a pseudo-random number in the range (0, 2**32).
        """
        if self.index >= _n:
            self.twist()
        y = self.state[self.index]
        self.index += 1
        return self.temper(y)

    def twist(self):
        # twist through the states and reset index to 0
        for i in range(_n):
            x = u32(
                (self.state[i] & UPPER_MASK) | (self.state[(i + 1) % _n] & LOWER_MASK)
            )
            # apply twist transformation A
            if x & 1:
                xA = (x >> 1) ^ _a
            else:
                xA = x >> 1
            self.state[i] = self.state[(i + _m) % _n] ^ xA
        self.index = 0

    def temper(self, y: int):
        # mix the bits of y
        # the purpose is to approximate an equi-distribution of (MSB) bits
        # so the returned value will appear "more random"
        y ^= y >> _u  #  & _d
        y ^= (y << _s) & _b
        y ^= (y << _t) & _c
        y ^= y >> _l
        return u32(y)

    def getstate(self) -> tuple[int, tuple, None]:
        # mimics the Python random.getstate function
        state = list(self.state) + [self.index]
        return (VERSION, tuple(state), None)

    def setstate(self, state: tuple):
        # mimics the Python setstate function
        # except that I ignore the last, `gauss_next` field
        assert len(state) == 3
        assert len(state[1]) == _n + 1
        istate, index = state[1][:-1], state[1][-1]
        assert 0 <= index <= _n
        self.index = index
        self.state = istate[:]

    def getrandbits(self, nbits: int):
        if nbits > 32:
            raise NotImplementedError()
        return self.generate() >> (32 - nbits)

    def randint(self, start: int, stop: int | None = None) -> int:
        return self.randrange(start, None if stop is None else stop + 1)

    def randrange(self, start: int, stop: int | None = None) -> int:
        if start > 0xFFFF_FFFF:
            raise NotImplementedError()

        if stop is None:
            assert start > 0
            return self._randbelow(start)

        assert start < stop
        return start + self._randbelow(stop - start)

    def _randbelow(self, n: int) -> int:
        # copied from stdlib random module
        getrandbits = self.getrandbits
        k = n.bit_length()
        r = getrandbits(k)
        while r >= n:
            r = getrandbits(k)
        return r

    def init_by_u32(self, seed: int):
        #
        # similar to CPython Modules/_randommodule.c init_by_array
        # with the restriction that seed should be a uint32
        #

        assert 0 <= seed <= 0xFFFF_FFFF

        # init_by_array first does a regular state (re)init using as seed 19650218
        self.initialize(19650218)

        i = 1
        state = self.state
        for k in range(_n, 0, -1):
            state[i] = u32(
                (state[i] ^ ((state[i - 1] ^ (state[i - 1] >> 30)) * 1664525)) + seed
            )
            i += 1
            if i >= _n:
                state[0] = state[_n - 1]
                i = 1
        for k in range(_n - 1, 0, -1):
            state[i] = u32(
                (state[i] ^ ((state[i - 1] ^ (state[i - 1] >> 30)) * 1566083941)) - i
            )
            i += 1
            if i >= _n:
                state[0] = state[_n - 1]
                i = 1

        state[0] = 0x8000_0000


def test_init(seed=0):
    import random

    random.seed(seed)
    mt = MersenneTwister(seed)

    # the internal states should now be equal
    state = random.getstate()[1]
    rstate, rindex = state[:-1], state[-1]

    assert rstate == tuple(mt.state)
    assert rindex == mt.index


def test_getset_state(seed=0):
    import random

    random.seed(seed)
    mt = MersenneTwister(seed=12345)
    mt.setstate(random.getstate())

    # the internal states should now be equal
    state = random.getstate()[1]
    rstate, rindex = state[:-1], state[-1]

    assert rstate == tuple(mt.state)
    assert rindex == mt.index


def test_generate(seed=0):
    import random

    random.seed(seed)
    mt = MersenneTwister(seed)

    for _ in range(100):
        i = random.randint(0, 0xFFFF_FFFE)
        j = mt.randint(0, 0xFFFF_FFFE)
        assert i == j


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Using default seed = 0")
        seed = 0
    else:
        v = sys.argv[1]
        if v.startswith("0x"):
            seed = int(v, 16)
        else:
            seed = int(sys.argv[1])
    test_init(seed)
    test_getset_state(seed)
    test_generate(seed)
    print("All tests OK")
