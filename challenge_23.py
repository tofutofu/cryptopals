# Clone an MT19937 RNG from its output

# Given 624 generated, successive output numbers, it's possible to reconstruct the MT19937 internal
# state. This is possible since (1) an output pseudo-random number is just the tempered form of a
# state value, (2) those outputs are returned, one after the other, in perfectly deterministic order,
# and (3) the `temper` function is invertible.
#
# Once you can reconstruct the internal state, you can predict what the PRNG will output next.
# Cloning the state basically boils down to implementing an `untemper` function that inverts the
# `temper` function.
#
# It's not easy, but it turns out to also not be _too_ hard to implement this `untemper` function.
#
# I considered using sympy for this, but sympy doesn't really have support for bitstring operations
# (or for combinations of logical operators and arithmethical shifts), and general usage is awkard
# and not intuitive. Z3, on the other hand, is much more intuitive in usage, has great support for
# bitvectors, and it's trivial to implement a solver that inverts the `untemper` function. I had
# seen one implementation earlier (which I'll copy below with minor modifications), but I also wanted
# to implement `untemper` myself - just to see how easy/difficult this would be.
#
# Initially I had a hard time trying to wrap my head around the problem of how to invert an operation
# like 'y = x ^ ((x << N) & M)', but this becomes straighforward if you think of the integers as
# bitvectors, consider which bits do not change, and translate the operations into bitstring ops.
#
# Doing so also shows you that the last two operations in `temper` are their own inverse -- something
# that remains hidden when you let Z3 do all the work! And it shows you _why_ the other operations are
# invertible. Finally, it may also make you wonder -- _what if_ temper was not invertible? Would it
# still work? What would the implications be? Was it necessary to use an invertible `temper` function?
#
# Other questions: What is the nature of the `temper` function? Is it a bijection (in the set of
# 32-bit non-negative integers)? Can the original seed be recovered?

import random
from challenge_21 import MersenneTwister


class U32:
    # An integer class to wrap (unsigned 32-bit) integers,
    # make them mutable and make them easier to use as bitvectors.
    #
    # Since Python integers are immutable, it's inconvenient to derive U32 from int.
    # It's not _impossible_ to do so, but you have to jump through some akward hoops.
    # I'll just use the easy way out.
    #
    # Since I'm only using this class in this exercise, I didn't bother to add
    # extensive error checking or error handling.

    def __init__(self, val: int = 0):
        self._val = int(val) & 0xFFFF_FFFF

    def __int__(self):
        return self._val

    def __index__(self):
        return self._val

    def __str__(self):
        return str(self._val)

    def __repr__(self):
        return str(self._val)

    def __xor__(self, other):
        return U32(int(self) ^ int(other))

    def __and__(self, other):
        return U32(int(self) & int(other))

    def __or__(self, other):
        return U32(int(self) | int(other))

    def __getitem__(self, index: int | slice) -> int:
        """
        >>> x = U32(0b10010110)
        >>> x[0]
        0
        >>> x[1]
        1
        >>> x[1:3]
        3
        >>> x[4:]
        9
        """
        if isinstance(index, int):
            assert 0 <= index < 32
            return int((self._val & (1 << index)) != 0)
        if isinstance(index, slice):
            i, j, stride = index.indices(32)  # not doing extensive error checking
            assert stride == 1  # only supporting contiguous substrings
            mask = ((1 << (j - i)) - 1) << i
            return (self._val & mask) >> i
        raise TypeError(
            f"Int indices must be integers or slices, not {index.__class__.__name__}"
        )

    def __setitem__(self, index: int | slice, val: int | bool):
        """
        >>> x = U32(0b10010110)
        >>> x[0] = 1; bin(x)
        '0b10010111'
        >>> x[0:3] = 0; bin(x)
        '0b10010000'
        >>> x[3:6] = 0b101; bin(x)
        '0b10101000'
        """
        if isinstance(index, int):
            assert 0 <= index < 32
            bit = 1 << index
            if int(val):
                self._val |= bit
            else:
                self._val &= 0xFFFF_FFFF ^ bit
        elif isinstance(index, slice):
            i, j, stride = index.indices(32)
            assert stride == 1
            # make mask consisting of (j - i) ones
            mask = (1 << (j - i)) - 1

            # ensure val doesn't overflow and shift it to the right bit position
            ival = (int(val) & mask) << i

            # shift mask to right bit position
            imask = mask << i

            # zero self[i:j]
            self._val &= 0xFFFF_FFFF ^ imask

            # plug in the val
            self._val |= ival
        else:
            raise TypeError(
                f"Int indices must be integers or slices, not {index.__class__.__name__}"
            )


def temper(y: int) -> int:
    """
    MT19937 temper.
    """
    y = y ^ (y >> 11)
    y = y ^ ((y << 7) & 0x9D2C5680)
    y = y ^ ((y << 15) & 0xEFC60000)
    y = y ^ (y >> 18)
    return y & 0xFFFF_FFFF


def untemper(y: int) -> int:
    """
    Inverse of MT19937 temper.

    >>> assert untemper(temper(0xABBA_BAAB)) == 0xABBA_BAAB
    >>> assert untemper(temper(0)) == 0
    >>> assert untemper(temper(1)) == 1
    >>> assert untemper(temper(0x9D2C5680)) == 0x9D2C5680
    >>> assert untemper(temper(0xFFFF_FFFF)) == 0xFFFF_FFFF
    """

    # the first two operations turn out to be their own inverses!
    y = y ^ (y >> 18)
    y = y ^ ((y << 15) & 0xEFC60000)

    # y = x ^ ((x << 7) & 0x9D2C5680) is not its own inverse :/
    # but we have
    #
    # y[0:7]   = x[0:7]
    # y[7:14]  = x[7:14] ^ (x[0:7] & 0x9D2C5680[7:14])
    # y[14:21] = x[14:21] ^ (x[7:14] & 0x9D2C5680[14:21])
    # y[21:28] = x[21:28] ^ (x[14:21] & 0x9D2C5680[21:28])
    # y[28:32] = x[28:32] ^ (x[21:25] & 0x0x9D2C5680[28:32])
    #
    # inverting this we get the following bitvector operations:

    y_ = U32(y)
    x = U32(0)
    M = U32(0x09D2C5680)

    x[0:7] = y_[0:7]
    x[7:14] = y_[7:14] ^ (x[0:7] & M[7:14])
    x[14:21] = y_[14:21] ^ (x[7:14] & M[14:21])
    x[21:28] = y_[21:28] ^ (x[14:21] & M[21:28])
    x[28:32] = y_[28:32] ^ (x[21:25] & M[28:32])
    y_ = x

    # y = x ^ (x >> 11) is also not its own inverse :)
    # but we have
    #
    # y[21:32] = x[21:32]
    # y[10:21] = x[10:21] ^ x[21:32]
    # y[0:10]  = x[0:10] ^ x[11:21]
    #
    # which is now very simple to invert:

    x = U32(0)
    x[21:32] = y_[21:32]
    x[10:21] = y_[10:21] ^ x[21:32]
    x[0:10] = y_[0:10] ^ x[11:21]
    y = int(x)

    return y


def untemper_using_z3(y: int) -> int:

    # Source: https://blog.infosectcbr.com.au/2019/08/cryptopals-challenge-23-clone-mt19937.html
    # See also: https://www.schutzwerk.com/en/blog/attacking-a-rng/
    # (I made a minor modification to the original code.)
    #
    # This is the "lazy" way of implementing the `untemper` function: Simply translate
    # the temper function into Z3 equations and let Z3 do the work. I'm quoting it here as
    # illustration of how easy it is to use Z3.

    from z3 import BitVec, BitVecVal, Solver, LShR, sat  # type: ignore

    y1 = BitVec("y1", 32)
    y2 = BitVec("y2", 32)
    y3 = BitVec("y3", 32)
    y4 = BitVec("y4", 32)
    y = BitVecVal(y, 32)
    s = Solver()

    equations = [
        y2 == y1 ^ (LShR(y1, 11)),
        y3 == y2 ^ ((y2 << 7) & 0x9D2C5680),
        y4 == y3 ^ ((y3 << 15) & 0xEFC60000),
        y == y4 ^ (LShR(y4, 18)),
    ]

    s.add(equations)
    if s.check() != sat:
        raise ValueError(f"Impossible to untemper {y}!?")
    return s.model()[y1].as_long()


# With the `untemper` function we can now recover the internal state
# of an MT19337 given a (consecutive) sequence of 624 generated 32-bit integers.
#
# If we get the last batch of generated integers, we clone the current state.
# At that point we don't need to know the index. We can just set it to 624.
#
# The main reason we can do so, is that the states are defined by a cyclical
# recurrence. One MT may have states (s0 s1 ... s623) and index 3, while another may
# have states (s3 s4 ... s623 ... s626) and idex 0, and they will then generate the
# same pseudo-random numbers. When the first one reaches `twist` and regenerates its
# state, the first 3 numbers will then become (s624 s625 s626 ...) due to way the
# twist is defined, so the PRNGs keep generating the same numbers.


def clone(data: list[int]) -> MersenneTwister:
    if len(data) < 624:
        raise ValueError(f"Need 624 or more numbers, but got only {len(data)}")

    mt = MersenneTwister()
    state = [untemper(x) for x in data[-624:]]
    state.append(624)

    mt.setstate((3, state, None))

    return mt


def break_mt1(seed: int = 20240401):
    mt = MersenneTwister()
    mt.seed(seed)
    assert mt.index == 624

    data = [mt.generate() for _ in range(624)]
    assert mt.index == 624

    mt1 = clone(data)
    assert mt1.index == mt.index
    assert mt1.state == mt.state

    for _ in range(2000):
        assert mt1.generate() == mt.generate()


def break_mt2(seed: int = 20240401):
    mt = MersenneTwister()
    mt.seed(seed)
    assert mt.index == 624

    mt.generate()
    mt.generate()
    mt.generate()
    assert mt.index == 3

    data = [mt.generate() for _ in range(624)]
    assert mt.index == 3

    mt1 = clone(data)
    assert mt1.index == 624

    # the state of m1 is now shifted in regards to mt
    # but the index is also shifted, so we still generate
    # the same random numbers

    for _ in range(2000):
        assert mt1.generate() == mt.generate()


def break_mt3(seed: int = 20240401):
    mt = MersenneTwister()
    mt.seed(seed)
    assert mt.index == 624

    mt.generate()
    mt.generate()
    mt.generate()
    assert mt.index == 3

    old_data = [mt.generate() for _ in range(624)]
    assert mt.index == 3

    for _ in range(19937):
        mt.generate()
    last = mt.generate()

    mt1 = clone(old_data)

    while True:
        if mt1.generate() == last:
            break

    for _ in range(2000):
        assert mt1.generate() == mt.generate()


if __name__ == "__main__":
    break_mt1()
    break_mt2()
    break_mt3()
    print("All tests OK")
