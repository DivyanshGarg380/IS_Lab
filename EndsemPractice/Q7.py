# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
Encrypt a medical record string using AES-128-CBC. 
Encrypt an authorization code using manually implemented ElGamal with p=467, g=2, x=127, k=53.
Verify the SHA-256 hash of the ciphertext and the recovered authorization code before decrypting the record. 
Demonstrate tampering detection.
'''

import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

p = 467
g = 2
x = 127
y = pow(g, x, p)
print("ElGamal Public Key:", (p, g, y))

auth_code = 123
expected_auth_code = 123
k = 53

c1 = pow(g, k, p)
c2 = (auth_code * pow(y, k, p)) % p

print("Encrypted Authorization:", (c1, c2))

record = input("Enter medical record: ")

aes_key = get_random_bytes(16)
cipher = AES.new(aes_key, AES.MODE_CBC)
iv = cipher.iv
ciphertext = cipher.encrypt(pad(record.encode(), AES.block_size))

print("Encrypted Record:", ciphertext.hex())
print("IV:", iv.hex())

stored_hash = hashlib.sha256(ciphertext).hexdigest()
print("Stored Hash:", stored_hash)

received_ciphertext = ciphertext

choice = input("Tamper with ciphertext? (yes/no): ").strip().lower()

if choice == "yes":
    modified = bytearray(received_ciphertext)
    modified[0] ^= 1
    received_ciphertext = bytes(modified)

received_hash = hashlib.sha256(received_ciphertext).hexdigest()

if received_hash != stored_hash:
    print("Integrity failed! Decryption denied.")
    raise SystemExit

print("Integrity verified!")

shared = pow(c1, x, p)
recovered_auth = (c2 * pow(shared, -1, p)) % p

print("Recovered Authorization:", recovered_auth)

if recovered_auth != expected_auth_code:
    print("Authorization failed! Decryption denied.")
    raise SystemExit

print("Authorization successful!")

cipher = AES.new(aes_key, AES.MODE_CBC, iv)

try:
    plaintext = unpad(cipher.decrypt(received_ciphertext),AES.block_size)
    print("Recovered AES Key:", aes_key.hex())
    print("Decrypted Medical Record:", plaintext.decode())

except ValueError:
    print("Decryption failed!")


