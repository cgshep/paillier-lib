#!/usr/bin/env python3

import gmpy2
from utils import generate_prime, lf, random_lt_n
from gmpy2 import lcm, gcd, invert, powmod, mpz

class PaillierKeyPair():
    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key


class PaillierPrivateKey():
    def __init__(self, l, u, n):
        self.l = l
        self.u = u
        self.n = n

class PaillierPublicKey():
    def __init__(self, n, g):
        self.n = n
        self.g = g


def encrypt(m, public_key):
    if m >= public_key.n:
        raise RuntimeException("Message size outside field!")
    r = random_lt_n(public_key.n)
    n_sqr = public_key.n ** 2
    a = powmod(public_key.g, m, n_sqr)
    b = powmod(r, public_key.n, n_sqr)
    return (a * b) % n_sqr


def decrypt(c, private_key):
    a = powmod(c, private_key.l, private_key.n ** 2)
    return lf(a, private_key.n) * private_key.u % private_key.n
 

def keygen(n_len=2048):
    n = 0
    p = q = None
    while n.bit_length() != n_len and p == q:
        p = generate_prime(n_len // 2)
        q = generate_prime(n_len // 2)
        n = p * q        

    l = lcm(p-1, q-1)
    if gcd(p*q, (p-1)*(q-1)) != 1:
        raise RuntimeException("Critical error: gcd(N,tot(N)) != 1")

    g = mpz()
    while gcd(g, n**2) != 1:
        g = random_lt_n(n)

    print("g:",g)
    u = invert(lf(powmod(g, l, n**2), n), n)
    public_key = PaillierPublicKey(n, g)
    private_key = PaillierPrivateKey(l, u, n)
    return PaillierKeyPair(public_key, private_key)


if __name__ == '__main__':
    p_pair = keygen()
    m = mpz(12)
    print("M:",m)
    c = encrypt(m, p_pair.public_key)
    print("Ciphertext:", c)
    print(gmpy2.bit_length(c))
    d = decrypt(c, p_pair.private_key)
    print("d:",d)
    
