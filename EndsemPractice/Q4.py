# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
Implement the Paillier cryptosystem manually without cryptographic libraries. 
Use p=7, q=11, g=n+1 to encrypt two medical charges, 5 and 8. Perform addition directly on their ciphertexts without decrypting them, then decrypt the result and verify that the total is 13.
'''

import math
import secrets

p = 7
q = 11

n = p * q
n2 = n * n
g = n + 1

lam = math.lcm(p - 1, q - 1)

def L(value):
    return (value - 1) // n

mu = pow(L(pow(g, lam, n2)), -1, n)

public_key = (n, g)
private_key = (lam, mu)

print("Public Key:", public_key)
print("Private Key:", private_key)

def encrypt(message):
    if not 0 <= message < n:
        raise ValueError("Message must be between 0 and n-1")

    r = secrets.randbelow(n - 1) + 1

    while math.gcd(r, n) != 1:
        r = secrets.randbelow(n - 1) + 1

    c1 = pow(g, message, n2)
    c2 = pow(r, n, n2)

    return (c1 * c2) % n2

def decrypt(ciphertext):
    value = pow(ciphertext, lam, n2)
    return (L(value) * mu) % n

charge1 = 5
charge2 = 8

c1 = encrypt(charge1)
c2 = encrypt(charge2)

print("\nCharge 1:", charge1)
print("Encrypted Charge 1:", c1)

print("\nCharge 2:", charge2)
print("Encrypted Charge 2:", c2)

encrypted_total = (c1 * c2) % n2

print("\nEncrypted Total:", encrypted_total)

total = decrypt(encrypted_total)

print("Decrypted Total:", total)
print("Expected Total:", charge1 + charge2)

if total == charge1 + charge2:
    print("Homomorphic addition verified!")
else:
    print("Verification failed!")
