# SECURE FILE TRANSFER

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import time


# RSA Key Generation

start = time.time()

key = RSA.generate(2048)
private_key = key
public_key = key.publickey()

key_generation_time = time.time() - start

print("RSA-2048 keys generated.")
print("Key Generation Time:", key_generation_time, "seconds")

data = b"Secure file transfer data"

# Encrypt

start = time.time()

cipher = PKCS1_OAEP.new(public_key)
encrypted_data = cipher.encrypt(data)

encryption_time = time.time() - start

print("Encryption completed.")
print("Encryption Time:", encryption_time, "seconds")

# Decrypt
start = time.time()

cipher = PKCS1_OAEP.new(private_key)
decrypted_data = cipher.decrypt(encrypted_data)

decryption_time = time.time() - start

print("Decryption completed.")
print("Decryption Time:", decryption_time, "seconds")

print("Original:", data)
print("Decrypted:", decrypted_data)
