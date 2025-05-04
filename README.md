## Cryptopals

These are my solutions to the [Cryptopals Challenges](https://cryptopals.com).

This is a set of 48 practical programming problems that give you a hands-on
crash course in understanding (and breaking) cryptographic ciphers. The problems
are fun to do, and (most importantly) do-able. An excellent introduction
can be found in [Maciej Ceglowski's](https://blog.pinboard.in/2013/04/the_matasano_crypto_challenges/)
blog post.

The exercises are bundled in 8 sets:

1. Basics (1-8)
2. Block crypto (9-16)
3. Block and stream crypto (17-24)
4. Stream crypto and randomness (25-32)
5. Diffie-Hellmann and friends (33-40)
6. RSA and DSA (41-48)
7. Hashes (49-56)
8. Abstract Algebra (57-66)

The most interesting challenges so far were challenges 21, 22, and 23, that implement the 
[MT19937 Mersenne Twister](https://en.wikipedia.org/wiki/Mersenne_Twister) PRNG and show how to break it.
This pseudo-random number generator  is very commonly used as a default PRNG (it's the default in the Python 
stdlib for instance) and despite its astronomically large state space, it turns out to be shockingly easy to break. 
Breaking it means to be able to predict all subsequent "random" numbers given a sequence of previously generated 
ones without knowledge of the original seed.

## Requirements

Python 3.10 or later.

Run `pip install -r requirements.txt` or do a conda install of packages listed in requirements.txt.


## Tests

Many solutions have doctests. To run them all, run
```
python -m doctest challenge_*.py --verbose
```

## Style

I ran all code through `ruff` and `black`. I generally also used typehints. Mypy didn't complain.
The typehints may sometimes be a bit unwieldy since I often couldn't decide if I wanted bytes or string
or integers as arguments, which would then lead to "Oh, what the heck, let's support them all."




