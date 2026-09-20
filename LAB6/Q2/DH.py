# Diffie-Hellman Key Exchange

# Public values
p = 23
g = 5

# Alice's private key
alice_private = 6

# Bob's private key
bob_private = 15


# Alice calculates her public key
alice_public = pow(g, alice_private, p)

# Bob calculates his public key
bob_public = pow(g, bob_private, p)


print("Public prime p:", p)
print("Public generator g:", g)

print("\nAlice's public key:", alice_public)
print("Bob's public key:", bob_public)


# Alice calculates shared secret
alice_shared = pow(
    bob_public,
    alice_private,
    p
)

# Bob calculates shared secret
bob_shared = pow(
    alice_public,
    bob_private,
    p
)


print("\nAlice's shared secret:", alice_shared)
print("Bob's shared secret:", bob_shared)


if alice_shared == bob_shared:
    print("Shared secret established successfully.")
else:
    print("Key exchange failed.")
