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


class PaillierCiphertext():
    def __init__(self, c, n):
        self.c = c
        self.n = n

    def __mul__(self, other):
        if self.n != other.n:
            raise RuntimeException("Both ciphertexts must have same bit-length!")
        return PaillierCiphertext((self.c * other.c) % self.n**2, self.n)

    def __pow__(self, other):
        return PaillierCiphertext((self.c ** other) % self.n**2, self.n)


def encrypt(m, public_key):
    if m >= public_key.n:
        raise RuntimeException("Message size outside field!")
    r = random_lt_n(public_key.n)
    n_sqr = public_key.n ** 2
    a = powmod(public_key.g, m, n_sqr)
    b = powmod(r, public_key.n, n_sqr)
    c = (a * b) % n_sqr
    return PaillierCiphertext(c, public_key.n)


def decrypt(p_c, private_key):
    c = p_c.c
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
    n_sqr = n**2
    while gcd(g, n_sqr) != 1:
        g = random_lt_n(n)

    u = invert(lf(powmod(g, l, n_sqr), n), n)
    public_key = PaillierPublicKey(n, g)
    private_key = PaillierPrivateKey(l, u, n)
    return PaillierKeyPair(public_key, private_key)


if __name__ == '__main__':
    p_pair = keygen()
    m = mpz(12)
    #print("M:",m)
    p_c = encrypt(m, p_pair.public_key)
    #print("Ciphertext:", p_c.c)
    #print(gmpy2.bit_length(p_c.c))
    d = decrypt(p_c, p_pair.private_key)
    print("d:",d)
    print("Testing homomorphism...")
    m1 = mpz(20)

    print("Addition, with m:",m1)
    p_c1 = encrypt(m1, p_pair.public_key)
    print(decrypt(p_c * p_c1, p_pair.private_key))
    print("Multiplication")
    print(decrypt(pow(p_c, m1), p_pair.private_key))
    
    
