# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    Hospital Prescription System
    - Doctor: create prescription .txt, encrypt using AES-128 CBC with user key + IV.
        - Hash the encrypted ciphertext using SHA-256.
        - Encrypt the AES key using RSA public key and store it.
        - Encrypt a given authorization code using ElGamal with given p, g, x.
    - Pharmacist: verify ciphertext hash → RSA-decrypt AES key → decrypt prescription → display plaintext.
    - Auditor: view hash, RSA-encrypted AES key, ElGamal ciphertext and verify authorization; cannot decrypt.
    - Add a tamper option that changes one byte of ciphertext and demonstrates integrity failure.
'''

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from sympy import randprime, gcd, mod_inverse
import hashlib
import os

ciphertext = b""
encrypted_hash = ""
original_hash = ""
rsa_encrypted_key = 0
elgamal_cipher = ()
authorization_code = 0

AES_KEY = b"0123456789ABCDEF"
IV = b"1234567890123456"

p = 1009
q = 1013

n = p * q
phi = (p - 1) * (q - 1)
e = 3
while gcd(e, phi) != 1:
    e += 2

d = mod_inverse(e, phi)

eg_p = 467
eg_g = 2
eg_x = 127
eg_y = pow(eg_g, eg_x, eg_p)

def elgamal_encrypt(m):
    k = 3

    while gcd(k, eg_p - 1) != 1:
        k += 1

    c1 = pow(eg_g, k, eg_p)
    shared = pow(eg_y, k, eg_p)
    c2 = (m * shared) % eg_p

    return c1, c2

def elgamal_decrypt(c1, c2):
    shared = pow(c1, eg_x, eg_p)
    inverse = pow(shared, -1, eg_p)
    return (c2 * inverse) % eg_p

def rsa_encrypt_key(key):
    key_int = int.from_bytes(key, "big")
    return pow(key_int, e, n)

def rsa_decrypt_key(encrypted_key):
    key_int = pow(encrypted_key, d, n)
    return key_int.to_bytes(16, "big")

# Doctor
def doctor():
    global ciphertext, encrypted_hash, original_hash
    global rsa_encrypted_key, elgamal_cipher, authorization_code

    filename = input("Enter prescription file: ")

    if not os.path.exists(filename):
        print("File not found.")
        return

    with open(filename, "rb") as file:
        data = file.read()

    # Original hash
    original_hash = hashlib.sha256(data).hexdigest()

    # AES-128 CBC
    cipher = AES.new(AES_KEY, AES.MODE_CBC, IV)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))

    with open("prescription.enc", "wb") as file:
        file.write(ciphertext)

    print("\nAES Ciphertext:", ciphertext.hex())
    
    # Hash encrypted ciphertext
    encrypted_hash = hashlib.sha256(ciphertext).hexdigest()

    print("SHA-256 Ciphertext Hash:", encrypted_hash)

    # RSA encrypt AES key
    rsa_encrypted_key = rsa_encrypt_key(AES_KEY)

    with open("rsa_key.txt", "w") as file:
        file.write(str(rsa_encrypted_key))

    print("RSA Encrypted AES Key:", rsa_encrypted_key)

    # ElGamal authorization
    authorization_code = int(input("Enter authorization code: "))

    if authorization_code >= eg_p:
        print("Authorization code must be smaller than p.")
        return

    elgamal_cipher = elgamal_encrypt(authorization_code)
    print("\nElGamal Public Key:", (eg_p, eg_g, eg_y))
    print("ElGamal Ciphertext:", elgamal_cipher)

    with open("metadata.txt", "w") as file:
        file.write(f"Hash={encrypted_hash}\n")
        file.write(f"RSAKey={rsa_encrypted_key}\n")
        file.write(f"ElGamal={elgamal_cipher}\n")

    print("\nPrescription secured successfully.")
    
# Pharmcist
def pharmacist():
    if not os.path.exists("prescription.enc"):
        print("No encrypted prescription.")
        return

    with open("prescription.enc", "rb") as file:
        data = file.read()

    # Verify encrypted ciphertext hash FIRST
    calculated_hash = hashlib.sha256(data).hexdigest()

    print("\nStored Hash:", encrypted_hash)
    print("Calculated Hash:", calculated_hash)

    if calculated_hash != encrypted_hash:
        print("INTEGRITY FAILED.")
        print("Decryption NOT performed.")
        return

    print("Integrity: VALID")

    # RSA decrypt AES key
    decrypted_key = rsa_decrypt_key(rsa_encrypted_key)

    print("RSA Decrypted AES Key:", decrypted_key.decode())
    # AES decrypt
    try:
        decipher = AES.new(decrypted_key, AES.MODE_CBC, IV)
        decrypted = unpad(decipher.decrypt(data), AES.block_size)
    except ValueError:
        print("AES Decryption Failed.")
        return

    # Verify original hash
    decrypted_hash = hashlib.sha256(decrypted).hexdigest()

    print("\nOriginal Hash:", original_hash)
    print("Decrypted Hash:", decrypted_hash)

    if decrypted_hash != original_hash:
        print("Original Integrity: FAILED")
        return

    print("Original Integrity: VALID")
    print("\nDecrypted Prescription:")
    print(decrypted.decode())

# Auditor
def auditor():
    print("Ciphertext Hash:", encrypted_hash)
    print("RSA Encrypted AES Key:", rsa_encrypted_key)
    print("ElGamal Public Key:", (eg_p, eg_g, eg_y))
    print("ElGamal Ciphertext:", elgamal_cipher)

    # Verify authorization without AES decryption
    if not elgamal_cipher:
        print("No authorization data.")
        return

    entered = int(input("Enter authorization code for verification: "))

    decrypted_auth = elgamal_decrypt(
        elgamal_cipher[0],
        elgamal_cipher[1]
    )

    if entered == decrypted_auth:
        print("Authorization: VALID")
    else:
        print("Authorization: INVALID")

    print("AES Decryption: NOT ALLOWED")
    print("Plaintext Access: NOT ALLOWED")
    
# Tamper now
def tamper():
    if not os.path.exists("prescription.enc"):
        print("No encrypted file.")
        return

    with open("prescription.enc", "rb") as file:
        data = bytearray(file.read())

    # Modify exactly one byte
    data[0] ^= 1

    with open("prescription.enc", "wb") as file:
        file.write(data)

    tampered_hash = hashlib.sha256(bytes(data)).hexdigest()

    print("\nStored Hash:", encrypted_hash)
    print("Tampered Hash:", tampered_hash)

    if tampered_hash != encrypted_hash:
        print("INTEGRITY FAILED - TAMPERING DETECTED.")
        print("Decryption must NOT be performed.")

while True:
    print("1. Doctor")
    print("2. Pharmacist")
    print("3. Auditor")
    print("4. Tamper Ciphertext")
    print("0. Exit")

    choice = int(input("Enter role: "))

    if choice == 1:
        doctor()
    elif choice == 2:
        pharmacist()
    elif choice == 3:
        auditor()
    elif choice == 4:
        tamper()
    elif choice == 0:
        break
    else:
        print("Invalid choice.")