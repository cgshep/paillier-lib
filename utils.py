import random
import gmpy2


def generate_prime(n_bits):
    rf = random.SystemRandom()
    r = gmpy2.mpz(rf.getrandbits(n_bits))
    r = gmpy2.bit_set(r, n_bits-1)
    return gmpy2.next_prime(r)


def random_lt_n(n):
    return random.SystemRandom().randrange(1, n)


def lf(x, n):
    return (x-1) // n
