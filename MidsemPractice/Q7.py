# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    Secure Employee Credentials

    - Employee: enter username/password → combine as username:password → encrypt using Vigenère → store encrypted credentials.
    - Compute MD5 of encrypted credentials.
    - Sign the encrypted MD5 hash using RSA private key.
    - Administrator: verify MD5 → verify RSA signature → decrypt Vigenère → verify original MD5.
    - Security Officer: view hashes and verify signature only.
    - RBAC compulsory.
'''

from sympy import randprime, gcd, mod_inverse
import hashlib
from datetime import datetime

p, q = 101, 103

n = p * q
phi = (p - 1) * (q - 1)
e = 3

d = mod_inverse(e, phi)

key = "SECURITY"

def vigenere_cipher(text, key, mode):
    result = ''
    key = key.upper()
    key_index = 0

    for ch in text:
        if ch.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')

            if mode == 'decrypt':
                shift = -shift

            if ch.isupper():
                base = ord('A')
            else:
                base = ord('a')

            result += chr((ord(ch) - base + shift) % 26 + base)
            key_index += 1
        else:
            result += ch

    return result

md5_original = ""
md5_encrypted = ""
encrypted_credentials = ""
signature = 0
timestamp = ""

# Employee
def employee():
    global md5_original, md5_encrypted, encrypted_credentials, signature, timestamp

    username = input("Enter username: ")
    password = input("Enter password: ")

    credentials = username + ":" + password
    
    # Store original credentials
    with open("credentials.txt", "w") as file:
        file.write(credentials)

    # Vigenere encryption
    encrypted_credentials = vigenere_cipher(credentials, key, "encrypt")

    with open("encrypted_credentials.txt", "w") as file:
        file.write(encrypted_credentials)

    print("\nEncrypted Credentials:", encrypted_credentials)

    # MD5 of original credentials
    md5_original = hashlib.md5(credentials.encode()).hexdigest()

    # MD5 of encrypted credentials
    md5_encrypted = hashlib.md5(encrypted_credentials.encode()).hexdigest()

    print("Original MD5:", md5_original)
    print("Encrypted MD5:", md5_encrypted)
    
    # RSA signature
    hash_int = int(md5_encrypted, 16)
    signature = pow(hash_int, d, n)

    print("RSA Signature:", signature)

    timestamp = datetime.now()

    print("Timestamp:", timestamp)

    with open("metadata.txt", "a") as file:
        file.write(f"Encrypted: {encrypted_credentials}\n")
        file.write(f"Original MD5: {md5_original}\n")
        file.write(f"Encrypted MD5: {md5_encrypted}\n")
        file.write(f"Signature: {signature}\n")
        file.write(f"Timestamp: {timestamp}\n")
        file.write("-" * 40 + "\n")


# Administrator
def administrator():
    with open("encrypted_credentials.txt", "r") as file:
        data = file.read()

    # Calculate MD5 of received encrypted credentials
    calculated_hash = hashlib.md5(data.encode()).hexdigest()

    print("\nStored MD5:", md5_encrypted)
    print("Calculated MD5:", calculated_hash)

    # Integrity check
    if calculated_hash == md5_encrypted:
        print("MD5 Integrity: VALID")
    else:
        print("MD5 Integrity: INVALID")
        print("Decryption not performed.")
        return

    # RSA signature verification
    verified_hash = pow(signature, e, n)
    stored_hash = int(md5_encrypted, 16) % n

    if verified_hash == stored_hash:
        print("RSA Signature: VALID")
    else:
        print("RSA Signature: INVALID")
        print("Unauthorized.")
        return
    
    # Vigenere decryption
    decrypted_credentials = vigenere_cipher(data, key, "decrypt")

    print("\nDecrypted Credentials:", decrypted_credentials)

    # Verify original credentials
    md5_decrypted = hashlib.md5(decrypted_credentials.encode()).hexdigest()

    print("MD5 of Decrypted Credentials:", md5_decrypted)

    if md5_decrypted == md5_original:
        print("Original Integrity: VALID")
    else:
        print("Original Integrity: INVALID")

    with open("verification.txt", "a") as file:
        file.write(f"Administrator | MD5: VALID | Signature: VALID | Timestamp: {datetime.now()}\n")


# Security Officer
def officer():
    print("Original MD5:", md5_original)
    print("Encrypted MD5:", md5_encrypted)
    print("Timestamp:", timestamp)

    # RSA signature verification
    verified_hash = pow(signature, e, n)
    stored_hash = int(md5_encrypted, 16) % n

    if verified_hash == stored_hash:
        print("RSA Signature: VALID")
    else:
        print("RSA Signature: INVALID")

    # RBAC restriction
    print("Credential Decryption: DENIED")
    print("Plaintext Access: DENIED")

while True:
    print("1. Employee")
    print("2. Administrator")
    print("3. Security Officer")
    print("0. Exit")

    choice = int(input("Enter role: "))

    if choice == 1:
        employee()

    elif choice == 2:
        administrator()

    elif choice == 3:
        officer()

    elif choice == 0:
        break

    else:
        print("Invalid choice.")