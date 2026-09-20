# Schnorr Digital Signature Demonstration

import hashlib

# Public parameters
p = 467
q = 233
g = 4

# Alice's private key
x = 123

# Alice's public key
y = pow(g, x, p)

message = "Alice's document"


def hash_value(message, r):
    data = str(r) + message

    return int(
        hashlib.sha256(data.encode()).hexdigest(),
        16
    ) % q


# Sign
def sign(message):

    # Random/selected nonce
    k = 17

    r = pow(g, k, p)

    e = hash_value(message, r)

    s = (k + x * e) % q

    return r, s


# Verify
def verify(message, signature):

    r, s = signature

    e = hash_value(message, r)

    left = pow(g, s, p)

    right = (r * pow(y, e, p)) % p

    return left == right


signature = sign(message)

print("Message:", message)
print("Public key:", y)
print("Private key:", x)
print("Signature:", signature)

if verify(message, signature):
    print("Schnorr signature verified.")
else:
    print("Signature verification failed.")
