# ElGamal Digital Signature Demonstration

import hashlib

# Public parameters
p = 467
g = 2

# Alice's private key
x = 127

# Alice's public key
y = pow(g, x, p)

message = "Alice's document"


# Hash the message
def hash_message(message):
    return int(
        hashlib.sha256(message.encode()).hexdigest(),
        16
    )


# Find modular inverse
def inverse(a, m):
    return pow(a, -1, m)


# Sign message
def sign(message):
    h = hash_message(message)

    # Choose k such that gcd(k, p-1) = 1
    k = 3

    r = pow(g, k, p)

    k_inv = inverse(k, p - 1)

    s = ((h - x * r) * k_inv) % (p - 1)

    return r, s


# Verify signature
def verify(message, r, s):

    h = hash_message(message)

    left = (pow(y, r, p) * pow(r, s, p)) % p
    right = pow(g, h, p)

    return left == right


signature = sign(message)

print("Message:", message)
print("Public key:", y)
print("Private key:", x)
print("Signature:", signature)

if verify(message, signature[0], signature[1]):
    print("Signature verified successfully.")
else:
    print("Signature verification failed.")
