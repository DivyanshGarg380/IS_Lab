
from Crypto.Util.number import getPrime, inverse, GCD


def generate_keypair(bits=1024):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)

    while p == q:
        q = getPrime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537

    while GCD(e, phi) != 1:
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        while p == q:
            q = getPrime(bits // 2)

        n = p * q
        phi = (p - 1) * (q - 1)

    d = inverse(e, phi)

    public_key = (e, n)
    private_key = (d, n)

    return public_key, private_key


def encrypt(public_key, message):
    e, n = public_key
    return pow(message, e, n)


def decrypt(private_key, ciphertext):
    d, n = private_key
    return pow(ciphertext, d, n)


def homomorphic_multiply(c1, c2, public_key):
    e, n = public_key
    return (c1 * c2) % n


public_key, private_key = generate_keypair()

a = 7
b = 3

ciphertext_a = encrypt(public_key, a)
ciphertext_b = encrypt(public_key, b)

print("Original integers:", a, b)
print("Ciphertext of a:", ciphertext_a)
print("Ciphertext of b:", ciphertext_b)

encrypted_product = homomorphic_multiply(ciphertext_a, ciphertext_b, public_key)

print("Encrypted product:", encrypted_product)

decrypted_product = decrypt(private_key, encrypted_product)

print("Decrypted product:", decrypted_product)
print("Expected product:", a * b)
print("Verification:", decrypted_product == a * b)
