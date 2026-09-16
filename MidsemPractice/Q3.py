# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    EduSecure - School Management System
'''

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from sympy import randprime, gcd, mod_inverse
import hashlib
from datetime import datetime

ciphertext = b""
signature = 0
original_hash = ""
encrypted_hash = ""
timestamp = ""
key = b"A1B2C3D4"

p, q = 1009, 1013
n = p * q
phi = (p - 1) * (q - 1)
e = 3
while gcd(e, phi) != 1:
    e += 2
    
d = mod_inverse(e, phi)

# Student
def student():
    global ciphertext, signature, original_hash, encrypted_hash, timestamp

    filename = input("Enter file name: ")
    with open(filename, "rb") as file:
        data = file.read()

    # Original hash
    original_hash = hashlib.sha256(data).hexdigest()

    # DES Encryption
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(data, DES.block_size))
    
    print("\nFile encrypted successfully.")
    print("Ciphertext (hex):", ciphertext.hex())

    # Store encrypted file
    with open("encrypted.txt", "wb") as file:
        file.write(ciphertext)

    # Hash encrypted record
    encrypted_hash = hashlib.sha256(ciphertext).hexdigest()

    print("Original Record Hash:", original_hash)
    print("Encrypted Record Hash:", encrypted_hash)

    # RSA Digital Signature
    hash_int = int(encrypted_hash, 16)
    signature = pow(hash_int, d, n)

    print("Digital Signature:", signature)

    timestamp = datetime.now()
    print("Timestamp:", timestamp)
    
    with open("metadata.txt", "a") as file:
        file.write(f"Filename: {filename}\n")
        file.write(f"Encrypted Hash: {encrypted_hash}\n")
        file.write(f"Original Hash: {original_hash}\n")
        file.write(f"Signature: {signature}\n")
        file.write(f"Timestamp: {timestamp}\n")
        file.write("-" * 50 + "\n")
        
# Faculty
def faculty():
    with open("encrypted.txt", "rb") as file:
        data = file.read()

    # Calculate hash of encrypted record
    calculated_hash = hashlib.sha256(data).hexdigest()

    print("\nStored Encrypted Hash:", encrypted_hash)
    print("Calculated Encrypted Hash:", calculated_hash)

    # Integrity check
    if calculated_hash != encrypted_hash:
        print("\nSHA-256 Integrity: INVALID")
        print("Decryption not performed.")
        return

    print("\nSHA-256 Integrity: VALID")

    # RSA Signature verification
    verified_hash = pow(signature, e, n)
    stored_hash = int(encrypted_hash, 16) % n

    if verified_hash != stored_hash:
        print("RSA Signature: INVALID")
        print("Decryption not performed.")
        return

    print("RSA Signature: VALID")

    # DES Decryption
    decipher = DES.new(key, DES.MODE_ECB)

    try:
        decrypted = unpad(decipher.decrypt(data), DES.block_size)
    except ValueError:
        print("Decryption failed.")
        return

    # Hash decrypted record
    decrypted_hash = hashlib.sha256(decrypted).hexdigest()

    print("SHA-256 of Decrypted Record:", decrypted_hash)

    if decrypted_hash == original_hash:
        print("SHA-256 Decrypted Record Integrity: VALID")
        print("Decrypted Record:", decrypted.decode())
    else:
        print("SHA-256 Decrypted Record Integrity: INVALID")
        
     # Store verification result
    with open("verification.txt", "a") as file:
        file.write(f"Faculty Verification | Integrity: VALID | Signature: VALID | Timestamp: {datetime.now()}\n")
        
    
# HOD
def hod():
    print("\nStored SHA-256 Hash Values")
    print("Original Record Hash:", original_hash)
    print("Encrypted Record Hash:", encrypted_hash)
    print("Timestamp:", timestamp)

    # RSA Signature verification
    verified_hash = pow(signature, e, n)
    stored_hash = int(encrypted_hash, 16) % n

    if verified_hash == stored_hash:
        print("RSA Signature: VALID")
    else:
        print("RSA Signature: INVALID")
        
while True:
    print("1. Student")
    print("2. Faculty")
    print("3. HOD")
    print("0. Exit")

    choice = int(input("Enter role: "))

    if choice == 1:
        student()

    elif choice == 2:
        faculty()

    elif choice == 3:
        hod()

    elif choice == 0:
        break

    else:
        print("Invalid choice.")