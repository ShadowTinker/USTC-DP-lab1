"""
"""
import random, sys 

from gmpy2 import mpz, powmod, invert, is_prime, random_state, mpz_urandomb, rint_round, log2, gcd, mpz_random, rint_floor, mul, div

rand=random_state(random.randrange(sys.maxsize))

class PrivateKey(object):
    def __init__(self, p, q, n):
        if p==q:
            self.l = p * (p-1)
        else:
            self.l = (p-1) * (q-1)
        try:
            self.m = invert(self.l, n)
        except ZeroDivisionError as e:
            print(e)
            exit()

class PublicKey(object):
    def __init__(self, n):
        self.n = n
        self.n_sq = n * n
        self.g = n + 1
        self.bits=mpz(rint_round(log2(self.n)))

def generate_prime(bits):    
    """Will generate an integer of b bits that is prime using the gmpy2 library  """    
    while True:
        possible =  mpz(2)**(bits-1) + mpz_urandomb(rand, bits-1 )
        if is_prime(possible):
            return possible

def generate_keypair(bits):
    """ Will generate a pair of paillier keys bits>5"""
    p = generate_prime(bits // 2)
    #print(p)
    q = generate_prime(bits // 2)
    #print(q)
    n = p * q
    return PrivateKey(p, q, n), PublicKey(n)

def enc(pub, plain):#(public key, plaintext)
    cipher = mpz()
    r = mpz_random(rand, pub.n)
    while (gcd(r, pub.n) != 1):
        r = mpz_random(rand, pub.n)
    cipher = powmod(mul(powmod(pub.g, plain, pub.n_sq), powmod(r, pub.n, pub.n_sq)), 1, pub.n_sq)
    return cipher

def dec(priv, pub, cipher): #(private key, public key, cipher)
    L = (pow(cipher, priv.l, pub.n_sq) - 1) // pub.n
    plain = (L * priv.m) % pub.n
    return plain

def enc_add(pub, m1, m2):
    return ((m1 * m2) % pub.n_sq)

def enc_add_const(pub, m, c):
    return (m * powmod(pub.g, c, pub.n_sq)) % pub.n_sq

def enc_mul_const(pub, m, c):
    return powmod(m, c, pub.n_sq)

if __name__ == '__main__':
    priv, pub = generate_keypair(1024)
    print('test basic encryption of 1212122147')
    cipher = enc(pub, mpz(1212122147))
    plain = dec(priv, pub, cipher)
    print('plaintext is', plain)
    print('test addition of 10010 and 121201212')
    cipher = enc_add(pub, enc(pub, 10010), enc(pub, 121201212))
    plain = dec(priv, pub, cipher)
    print('plaintext is', plain)
    print('test addition of ciphertext 10010 and plaintext 121201212')
    cipher = enc_add_const(pub, enc(pub, 10010), 121201212)
    plain = dec(priv, pub, cipher)
    print('plaintext is', plain)
    print('test multiplication of ciphertext 10010 and plaintext 121201212')
    cipher = enc_mul_const(pub, enc(pub, 10010), 121201212)
    plain = dec(priv, pub, cipher)
    print('plaintext is', plain)

