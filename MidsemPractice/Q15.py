# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    Secure Academic Records

    - Roles: Student, Faculty, HoD

    - Student: read message.txt → DES encrypt → store in encrypted.txt → SHA-256 of encrypted data → ElGamal digital signature → store signature/hash/timestamp.
    - Faculty: view encrypted record → verify SHA-256 + ElGamal signature → decrypt DES → display original record.
    - HoD: view only record ID/hash/timestamp → verify ElGamal signature → cannot decrypt.
    - Use RBAC and files.
    - Include tampering detection.
    
    Based out of IT-B's question
'''

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import hashlib
from datetime import datetime 
from math import gcd 

key = b"A1B2C3D4"

p = 467
g = 2
x = 127
k = 53
y = pow(g, x, p)

input_file = "message.txt"
encrypted_file = "encrypted.txt"
metadata_file = "metadata.txt"

def elgamal_sign(hash_value):
    h = int(hash_value, 16) % (p - 1)
    r = pow(g, k, p)
    k_inv = pow(k, -1, p - 1)
    s = (k_inv * (h - x * r)) % (p - 1)
    return r, s

def elgamal_verify(hash_value, r, s):
    h = int(hash_value, 16) % (p - 1)
    left = pow(g, h, p)
    right = (pow(y, r, p) * pow(r, s, p)) % p
    return left == right

# Student
def student():
    with open(input_file, "rb") as file:
        data = file.read()

    cipher = DES.new(key, DES.MODE_ECB)

    ciphertext = cipher.encrypt(pad(data, DES.block_size))

    with open(encrypted_file, "wb") as file:
        file.write(ciphertext)
        
    hash_val = hashlib.sha256(ciphertext).hexdigest()
    r, s = elgamal_sign(hash_val)
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(metadata_file, "w") as file:
        file.write(hash_val + "\n")
        file.write(str(r) + "\n")
        file.write(str(s) + "\n")
        file.write(timestamp + "\n")

    print("File encrypted successfully.")
    print("Ciphertext:", ciphertext.hex())
    print("SHA-256:", hash_val)
    print("ElGamal Signature:", (r, s))
    print("Timestamp:", timestamp)
    
    
# Faculty
def faculty_view():
    try:
        with open(encrypted_file, "rb") as file:
            ciphertext = file.read()

        with open(metadata_file, "r") as file:
            hash_value = file.readline().strip()
            r = int(file.readline().strip())
            s = int(file.readline().strip())
            timestamp = file.readline().strip()

        print("Encrypted Data:", ciphertext.hex())
        print("SHA-256:", hash_value)
        print("ElGamal Signature:", (r, s))
        print("Timestamp:", timestamp)

    except FileNotFoundError:
        print("Required files not found.")
        

def faculty_decrypt():
    try:
        with open(encrypted_file, "rb") as file:
            ciphertext = file.read()

        with open(metadata_file, "r") as file:
            stored_hash = file.readline().strip()
            r = int(file.readline().strip())
            s = int(file.readline().strip())

    except FileNotFoundError:

        print("Required files not found.")
        return

    curr_hash = hashlib.sha256(ciphertext).hexdigest()
    
    if curr_hash == stored_hash:
        print("SHA-256 Integrity: VALID")
    else:
        print("SHA-256 Integrity: INVALID")
        print("Decryption denied.")
        return
    
    if elgamal_verify(curr_hash, r, s):
        print("ElGamal Signature: VALID")
    else:
        print("ElGamal Signature: INVALID")
        print("Decryption denied.")
        return
    
    cipher = DES.new(key, DES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
    print("Decrypted Record:", plaintext.decode())
    
# HoD
def hod_view():
    try:
        with open(metadata_file, "r") as file:
            hash_value = file.readline().strip()
            r = file.readline().strip()
            s = file.readline().strip()
            timestamp = file.readline().strip()

        print("SHA-256 Hash:", hash_value)
        print("ElGamal Signature:", (r, s))
        print("Timestamp:", timestamp)

    except FileNotFoundError:
        print("Required files not found.")
        
        
def hod_verify():
    try:
        with open(encrypted_file, "rb") as file:
            ciphertext = file.read()

        with open(metadata_file, "r") as file:
            stored_hash = file.readline().strip()
            r = int(file.readline().strip())
            s = int(file.readline().strip())

    except FileNotFoundError:
        print("Required files not found.")
        return
    
    current_hash = hashlib.sha256(ciphertext).hexdigest()

    if current_hash == stored_hash:
        print("SHA-256 Integrity: VALID")
    else:
        print("SHA-256 Integrity: INVALID")

    if elgamal_verify(current_hash, r, s):
        print("ElGamal Signature: VALID")
    else:
        print("ElGamal Signature: INVALID")
        
        
# Tamper
def tamper_file():
    try:
        with open(encrypted_file, "rb") as file:
            data = bytearray(file.read())

        data[0] ^= 1
        with open(encrypted_file, "wb") as file:
            file.write(data)

        print("Encrypted file modified.")

    except FileNotFoundError:
        print("Encrypted file not found.")

        
while True:
    print("1. Student")
    print("2. Faculty")
    print("3. HoD")
    print("4. Exit")

    role = int(input("Enter Role: "))

    if role == 1:
        while True:
            print("1. Encrypt and Upload")
            print("2. Tamper Test")
            print("3. Back")

            choice = int(input("Enter choice: "))

            if choice == 1:
                student()

            elif choice == 2:
                tamper_file()

            elif choice == 3:
                break

            else:
                print("Invalid choice.")

    elif role == 2:
        while True:
            print("1. View Encrypted Record")
            print("2. Verify and Decrypt")
            print("3. Back")

            choice = int(input("Enter choice: "))

            if choice == 1:
                faculty_view()

            elif choice == 2:
                faculty_decrypt()

            elif choice == 3:
                break

            else:
                print("Invalid choice.")

    elif role == 3:
        while True:
            print("1. View Hash and Signature")
            print("2. Verify Signature")
            print("3. Back")

            choice = int(input("Enter choice: "))

            if choice == 1:
                hod_view()

            elif choice == 2:
                hod_verify()

            elif choice == 3:
                break

            else:
                print("Invalid choice.")

    elif role == 4:
        print("Exiting...")
        break

    else:
        print("Invalid role.")