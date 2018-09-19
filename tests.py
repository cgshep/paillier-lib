import paillier

from gmpy2 import mpz

m1 = mpz(10)
m2 = mpz(1)
m3 = mpz(0)
m4 = mpz(2000)
m5 = mpz(4000)
m6 = mpz(999)

key_pair = paillier.keygen()
c1 = paillier.encrypt(m1, key_pair.public_key)
c2 = paillier.encrypt(m2, key_pair.public_key)
c3 = paillier.encrypt(m3, key_pair.public_key)
c4 = paillier.encrypt(m4, key_pair.public_key)
c5 = paillier.encrypt(m5, key_pair.public_key)
c6 = paillier.encrypt(m6, key_pair.public_key)
    
def test_additive():
    assert paillier.decrypt(c1 + c2, key_pair.private_key) == 11
    assert paillier.decrypt(c1 + c2 + c1, key_pair.private_key) == 21
    assert paillier.decrypt(c1 + c2 + c1 + c2, key_pair.private_key) == 22
    assert paillier.decrypt(c6 + c2, key_pair.private_key) == 1000
    assert paillier.decrypt(c5 + c6 + c5, key_pair.private_key) == 8999
    assert paillier.decrypt(c3 + c3 + c3 + c3 + c3, key_pair.private_key) == 0

def test_sub():
    assert paillier.decrypt(c2 - c3, key_pair.private_key) == 1
    assert paillier.decrypt(c2 - c3 - c3 - c3, key_pair.private_key) == 1
    assert paillier.decrypt(c5 - c4 - c2, key_pair.private_key) == 1999
    assert paillier.decrypt(c2 + c3 + c2 - c3 - c2, key_pair.private_key) == 1 

def test_mul():
    assert paillier.decrypt(c1 * m2, key_pair.private_key) == 10
    assert paillier.decrypt(c1 * m1, key_pair.private_key) == 100
    assert paillier.decrypt(c1 * m1 * m1 * m1 * m2, key_pair.private_key) == 10000
    assert paillier.decrypt(c5 * m3, key_pair.private_key) == 0
    # TODO: more tests
