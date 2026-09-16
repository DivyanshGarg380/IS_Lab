# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    Secure Hospital Billing System

    - Receptionist: create billing .txt, encrypt using AES-128 CBC, hash encrypted ciphertext using SHA-256, RSA-sign the hash.
    - Accountant: verify hash → verify RSA signature → decrypt and display bill.
    - Auditor: view encrypted hash + timestamp and verify signature only.
    - Tamper option: modify one byte of ciphertext and show integrity failure.
    - Implement RBAC using menu.
'''

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from sympy import randprime, gcd, mod_inverse
import hashlib
from datetime import datetime

ciphertext = ""
original_hash = ""
encrypted_hash = ""
signature = 0
timestamp = ""

key = b"0123456789ABCDEF"
iv = b"1234567890123456"

p = 1009
q = 1013
n = p * q
phi = (p - 1) * (q - 1)
e = 3
    
d = mod_inverse(e, phi)

print("RSA Public Key :", (n, e))
print("RSA Private Key:", (n, d))

# Receptionist
def receptionist():
    filename = input("Enter billing file name")
    with open(filename, "rb") as file:
        data = file.read()
        
    print("\nOriginal Bill: ", data.decode())
    
    # Hash original data
    original_hash = hashlib.sha256(data).hexdigest()
    print("Original SHA-256:", original_hash)
    
    # AES-128 CBC Encryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    print("\nEncrypted Bill (hex):", ciphertext.hex())
    
    # Store encrypted file
    with open("Encrypted_bill.txt", "wb") as file:
        file.write(ciphertext)
        
    # Hash encrypted data
    encrypted_hash = hashlib.sha256(ciphertext).hexdigest()
    
    print("Encrypted SHA-256:", encrypted_hash)
    
    # RSA Digital Signature
    hash_int = int(encrypted_hash, 16)
    signature = pow(hash_int, d, n)
    print("Digital Signature:", signature)
    
    # Timestamp
    timestamp = datetime.now()

    print("Timestamp:", timestamp)
    
    # Store metadata
    with open("bill_metadata.txt", "a") as file:
        file.write(f"Encrypted Hash: {encrypted_hash}\n")
        file.write(f"Signature: {signature}\n")
        file.write(f"Timestamp: {timestamp}\n")
        file.write("--------------------------------\n")
        
    print("\nBill encrypted and stored successfully.")
    

# Accountant
def accountant():
    with open("encrypted_bill.txt", "rb") as file:
        data = file.read()
        
    # Calculate hash of received ciphertext
    calculated_hash = hashlib.sha256(data).hexdigest()
    
    print("Stored Hash:", encrypted_hash)
    print("Calculated Hash:", calculated_hash)

    # Integrity verification
    if calculated_hash == encrypted_hash:
        print("SHA-256 Integrity: VALID")
        
    else:
        print("SHA-256 Integrity: INVALID")
        print("Decryption not performed.")
        return
    
    # RSA Signature Verification
    verified_hash = pow(signature, e, n)
    stored_hash = int(encrypted_hash, 16) % n
    if verified_hash == stored_hash:
        print("RSA Signature: VALID")
        
    else:
        print("RSA Signature: INVALID")
        print("Decryption not performed.")
        return
    
    # AES Decryption
    decipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        decrypted = unpad(decipher.decrypt(data), AES.block_size)
        
    except ValueError:
        print("Decryption Failed!")
        return
    
    print("\nDecrypted Bill:", decrypted.decode())

    # Verify decrypted data
    decrypted_hash = hashlib.sha256(decrypted).hexdigest()

    print("Decrypted SHA-256:", decrypted_hash)

    if decrypted_hash == original_hash:
        print("Original Data Integrity: VALID")

    else:
        print("Original Data Integrity: INVALID")
        
def auditor():
    print("Encrypted SHA-256:", encrypted_hash)
    print("Timestamp:", timestamp)
    
    # Verify RSA signature
    verified_hash = pow(signature, e, n)
    stored_hash = int(encrypted_hash, 16) % n

    if verified_hash == stored_hash:
        print("RSA Signature: VALID")

    else:
        print("RSA Signature: INVALID")

    # RBAC
    print("Plaintext Access: DENIED")
    print("Decryption Access: DENIED")

def tamper():
    global ciphertext
    
    with open("encrypted_bill.txt", "rb") as file:
        data = bytearray(file.read())

    # Modify one byte
    data[0] ^= 1

    with open("encrypted_bill.txt", "wb") as file:
        file.write(data)

    print("One byte of encrypted file modified.")

    tampered_hash = hashlib.sha256(bytes(data)).hexdigest()

    print("Original Hash:", encrypted_hash)
    print("Tampered Hash:", tampered_hash)

    if tampered_hash == encrypted_hash:
        print("Integrity: VALID")

    else:
        print("Integrity: FAILED")
        print("Tampering detected.")
        
while True:
    print("1. Receptionist")
    print("2. Accountant")
    print("3. Auditor")
    print("4. Tamper Encrypted File")
    print("0. Exit")

    choice = int(input("Enter role: "))

    if choice == 1:
        receptionist()

    elif choice == 2:
        accountant()

    elif choice == 3:
        auditor()

    elif choice == 4:
        tamper()

    elif choice == 0:
        break

    else:

        print("Invalid choice.")