# P2P FILE SHARING + DIFFIE-HELLMAN

import time

# Public parameters
p = int(input("Enter prime number p: "))
g = int(input("Enter generator g: "))

# Start measuring key generation
start = time.time()

# Private keys of both peers
a = int(input("Enter Peer A private key: "))
b = int(input("Enter Peer B private key: "))

# Generate public keys
A = pow(g, a, p)
B = pow(g, b, p)

key_generation_time = time.time() - start

print("\n--- Public Keys ---")
print("Peer A Public Key:", A)
print("Peer B Public Key:", B)

# Measure key exchange
start = time.time()

# Both peers independently calculate the shared secret
secret_A = pow(B, a, p)
secret_B = pow(A, b, p)

key_exchange_time = time.time() - start

print("\n--- Shared Secret ---")
print("Peer A Shared Secret:", secret_A)
print("Peer B Shared Secret:", secret_B)

# Verify
if secret_A == secret_B:
    print("\nKey Exchange Successful!")
    print("Both peers have the same shared secret.")
else:
    print("\nKey Exchange Failed!")

print("\n--- Performance ---")
print("Key Generation Time:", key_generation_time, "seconds")
print("Key Exchange Time:", key_exchange_time, "seconds")