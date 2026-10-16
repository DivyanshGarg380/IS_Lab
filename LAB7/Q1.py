
from Crypto.Util.number import getPrime, inverse, GCD
import random
import math


def generate_keypair(bits=512):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)

    while p == q:
        q = getPrime(bits // 2)

    n = p * q
    g = n + 1
    lam = math.lcm(p - 1, q - 1)

    n_squared = n * n
    x = pow(g, lam, n_squared)
    L = (x - 1) // n
    mu = inverse(L, n)

    public_key = (n, g)
    private_key = (lam, mu)

    return public_key, private_key


def encrypt(public_key, message):
    n, g = public_key
    n_squared = n * n

    if not 0 <= message < n:
        raise ValueError("Message must be between 0 and n-1")

    while True:
        r = random.randrange(1, n)
        if GCD(r, n) == 1:
            break

    ciphertext = (
        pow(g, message, n_squared)
        * pow(r, n, n_squared)
    ) % n_squared

    return ciphertext


def decrypt(public_key, private_key, ciphertext):
    n, g = public_key
    lam, mu = private_key
    n_squared = n * n

    x = pow(ciphertext, lam, n_squared)
    L = (x - 1) // n

    return (L * mu) % n


def homomorphic_add(c1, c2, public_key):
    n, g = public_key
    return (c1 * c2) % (n * n)


public_key, private_key = generate_keypair()

a = 15
b = 25

ciphertext_a = encrypt(public_key, a)
ciphertext_b = encrypt(public_key, b)

print("Original integers:", a, b)
print("Ciphertext of a:", ciphertext_a)
print("Ciphertext of b:", ciphertext_b)

encrypted_sum = homomorphic_add(ciphertext_a, ciphertext_b, public_key)

print("Encrypted sum:", encrypted_sum)

decrypted_sum = decrypt(public_key, private_key, encrypted_sum)

print("Decrypted sum:", decrypted_sum)
print("Expected sum:", a + b)
print("Verification:", decrypted_sum == a + b)
