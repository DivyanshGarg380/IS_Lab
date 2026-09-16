# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    Secure Payroll System
    - Employee: create .txt salary record, encrypt using AES-128 CBC with user-provided key + IV, hash encrypted data using SHA-256, sign hash using RSA private key, store metadata.
    - Manager: verify encrypted hash → verify RSA signature → decrypt → display plaintext.
    - Auditor: view only hash + timestamp and verify RSA signature.
    - If integrity/signature fails → do not decrypt.
    - Menu-driven RBAC.
'''

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from sympy import randprime, gcd, mod_inverse
import hashlib
from datetime import datetime
import os

ciphertext = b""
encrypted_hash = ""
original_hash = ""
signature = 0
timestamp = ""

p = 103
q = 107
n = p * q
phi = (p - 1) * (q - 1)

e = 3
while gcd(e, phi) != 1:
    e += 2

d = mod_inverse(e, phi)

# Employee
def employee():
    global ciphertext, encrypted_hash, original_hash, signature, timestamp

    filename = input("Enter file name: ")

    key = input("Enter AES-128 key (16 characters): ").encode()
    iv = input("Enter IV (16 characters): ").encode()

    if len(key) != 16 or len(iv) != 16:
        print("Key and IV must be 16 bytes.")
        return

    with open(filename, "rb") as file:
        data = file.read()

    original_hash = hashlib.sha256(data).hexdigest()

    # AES-128 encryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))

    with open("salary_encrypted.txt", "wb") as file:
        file.write(ciphertext)

    print("\nEncrypted Data:", ciphertext.hex())

    # Hash encrypted data
    encrypted_hash = hashlib.sha256(ciphertext).hexdigest()

    print("SHA-256:", encrypted_hash)

    # RSA signature
    hash_int = int(encrypted_hash, 16)
    signature = pow(hash_int, d, n)

    print("Digital Signature:", signature)

    timestamp = datetime.now()

    with open("metadata.txt", "a") as file:
        file.write(f"File: {filename}\n")
        file.write(f"Hash: {encrypted_hash}\n")
        file.write(f"Signature: {signature}\n")
        file.write(f"Timestamp: {timestamp}\n")
        file.write("-" * 40 + "\n")

    # Store AES credentials for this practice program
    with open("aes_info.txt", "w") as file:
        file.write(key.hex() + "\n")
        file.write(iv.hex())

    print("Record stored successfully.")

# Manager
def manager():
    if not os.path.exists("salary_encrypted.txt"):
        print("No encrypted record found.")
        return

    key = input("Enter AES-128 key (16 characters): ").encode()
    iv = input("Enter IV (16 characters): ").encode()

    if len(key) != 16 or len(iv) != 16:
        print("Key and IV must be 16 bytes.")
        return

    with open("salary_encrypted.txt", "rb") as file:
        data = file.read()

    # Step 1: Integrity
    calculated_hash = hashlib.sha256(data).hexdigest()

    print("\nStored Hash:", encrypted_hash)
    print("Calculated Hash:", calculated_hash)

    if calculated_hash != encrypted_hash:
        print("Integrity: INVALID")
        print("Decryption not performed.")
        return

    print("Integrity: VALID")
    
    # Step 2: Signature
    verified_hash = pow(signature, e, n)
    stored_hash = int(encrypted_hash, 16) % n

    if verified_hash != stored_hash:
        print("RSA Signature: INVALID")
        print("Decryption not performed.")
        return

    print("RSA Signature: VALID")

    # Step 3: Decryption
    try:
        decipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(decipher.decrypt(data), AES.block_size)
    except ValueError:
        print("AES decryption failed.")
        return

    print("\nDecrypted Salary Record:")
    print(decrypted.decode())

    # Step 4: Original hash
    decrypted_hash = hashlib.sha256(decrypted).hexdigest()

    print("\nOriginal Hash:", original_hash)
    print("Decrypted Hash:", decrypted_hash)

    if decrypted_hash == original_hash:
        print("Original Record Integrity: VALID")
    else:
        print("Original Record Integrity: INVALID")

# Auditor
def auditor():
    if not encrypted_hash:
        print("No record available.")
        return

    print("\nFilename: salary_encrypted.txt")
    print("SHA-256 Hash:", encrypted_hash)
    print("Timestamp:", timestamp)

    # Verify signature without decrypting
    verified_hash = pow(signature, e, n)
    stored_hash = int(encrypted_hash, 16) % n

    if verified_hash == stored_hash:
        print("RSA Signature: VALID")
    else:
        print("RSA Signature: INVALID")

    print("Plaintext access: DENIED")
    print("Decryption access: DENIED")
    
while True:
    print("1. Employee")
    print("2. Manager")
    print("3. Auditor")
    print("0. Exit")

    choice = int(input("Enter role: "))

    if choice == 1:
        employee()
    elif choice == 2:
        manager()
    elif choice == 3:
        auditor()
    elif choice == 0:
        break
    else:
        print("Invalid choice.")