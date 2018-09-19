from .utils import generate_prime, lf, random_lt_n
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
        self.n_sqr = n**2

class PaillierPublicKey():
    def __init__(self, n, g):
        self.n = n
        self.g = g
        self.n_sqr = n**2

class PaillierCiphertext():
    def __init__(self, c, n):
        self.c = c
        self.n = n
        self.n_sqr = n**2

    def __add__(self, other):
        return PaillierCiphertext((self.c * other.c) % self.n_sqr, self.n)

    def __radd__(self, other):
        return __add__(self, other)

    def __mul__(self, other):
        return PaillierCiphertext((self.c ** other) % self.n_sqr, self.n)

    def __rmul__(self, other):
        return __mul__(self, other)

    def __sub__(self, other):
        return PaillierCiphertext((self.c * invert(other.c, self.n_sqr)) % self.n_sqr, self.n)

    def __rsub__(self, other):
        return __sub__(self, other)

    
def encrypt(m, public_key):
    r = random_lt_n(public_key.n)
    a = powmod(public_key.g, m, public_key.n_sqr)
    b = powmod(r, public_key.n, public_key.n_sqr)
    c = (a * b) % public_key.n_sqr
    return PaillierCiphertext(c, public_key.n)

def decrypt(p_c, private_key):
    c = p_c.c
    a = powmod(c, private_key.l, private_key.n_sqr)
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
    
