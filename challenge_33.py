# Diffie-Hellman

import random


def generate_private_key(p: int = 37):
    return random.randint(0, 1000) % 37


def generate_public_key(a: int, p: int = 37, g: int = 5):
    return pow(g, a, p)


def modexp1(b: int, e: int, m: int) -> int:
    """
    Equivalent to pow(b, e, m).

    Returns (b ** e) % m

    >>> assert modexp1(4, 13, 497) == (4 ** 13) % 497
    """
    if m == 1:
        return 0
    c = 1
    if m.bit_count() == 1:  # m is a power of 2
        mask = m - 1
        while e:
            c = (b * c) & mask
            e -= 1
    else:
        while e:
            c = (b * c) % m
            e -= 1
    return c


def modexp2(b: int, e: int, m: int) -> int:
    """
    Equivalent to pow(b, e, m).

    Returns (b ** e) % m

    This method is about 1.4x as fast as modexp1.
    It's only about 3x as slow as the built-in pow function.

    >>> assert modexp2(4, 13, 497) == (4 ** 13) % 497
    """
    if m == 1:
        return 0
    c = 1
    if m.bit_count() == 1:
        mask = m - 1
        b = b & mask
        while e:
            if e & 1:
                c = (c * b) & mask
            e >>= 1
            b = (b * b) & mask
    else:
        b = b % m
        while e:
            if e & 1:
                c = (c * b) % m
            e >>= 1
            b = (b * b) % m
    return c


def test(p: int, g: int):
    a = generate_private_key(p)
    b = generate_private_key(p)
    A = generate_public_key(a, p, g)
    B = generate_public_key(b, p, g)

    s1 = pow(B, a, p)
    s2 = pow(A, b, p)

    assert s1 == s2


def test1():
    test(p=37, g=5)


def test2():
    ps = """
    ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
    e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
    3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
    6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
    24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
    c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
    bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
    fffffffffffff
    """

    p = int("".join(x.strip() for x in ps.split("\n")), 16)

    test(p=p, g=2)
