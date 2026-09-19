# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    A company stores salary records securely using 3DES-CBC + SHA-256 + RSA Digital Signature + RBAC.

    - Roles
        - HR Officer: create/encrypt record, generate hash + RSA signature.
        - Manager: verify hash + signature, then decrypt and view record.
        - Auditor: view metadata and verify signature only; cannot decrypt.

    - Add a Tamper File option that changes one byte of the encrypted file.
'''

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import hashlib
from datetime import datetime
import os

p = 61
q = 53
e = 17
d = 2753
n = p * q

key = b"A1B2C3D4E5F60708"
iv = b"12345678"

# HR Officer
def hr_officer():
    message = input("Enter salary record: ")
    plaintext = message.encode()

    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, DES3.block_size))

    with open("salary.enc", "wb") as file:
        file.write(ciphertext)

    hash_value = hashlib.sha256(ciphertext).hexdigest()
    hash_int = int(hash_value, 16) % n

    signature = pow(hash_int, d, n)

    with open("metadata.txt", "w") as file:
        file.write("SHA256=" + hash_value + "\n")
        file.write("Signature=" + str(signature) + "\n")
        file.write("Timestamp=" + str(datetime.now()) + "\n")

    print("Salary record encrypted successfully")
    print("SHA-256:", hash_value)
    print("RSA Signature:", signature)
    
def read_metadata():
    data = {}
    with open("metadata.txt", "r") as file:
        for line in file:
            key_name, value = line.strip().split("=", 1)
            data[key_name] = value

    return data

# Manager
def manager():
    metadata = read_metadata()

    stored_hash = metadata["SHA256"]
    signature = int(metadata["Signature"])

    with open("salary.enc", "rb") as file:
        ciphertext = file.read()

    current_hash = hashlib.sha256(ciphertext).hexdigest()

    if current_hash != stored_hash:
        print("Hash verification failed")
        print("File has been tampered")
        return

    print("Hash verification successful")

    hash_int = int(current_hash, 16) % n
    verified_hash = pow(signature, e, n)

    if verified_hash != hash_int:
        print("RSA Signature Invalid")
        return

    print("RSA Signature Valid")

    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    plaintext = unpad(
        cipher.decrypt(ciphertext),
        DES3.block_size
    )

    print("Original Salary Record:", plaintext.decode())
    
# Auditor
def auditor():
    metadata = read_metadata()

    stored_hash = metadata["SHA256"]
    signature = int(metadata["Signature"])

    print("SHA-256:", stored_hash)
    print("Signature:", signature)
    print("Timestamp:", metadata["Timestamp"])

    hash_int = int(stored_hash, 16) % n
    verified_hash = pow(signature, e, n)

    if verified_hash == hash_int:
        print("Signature Valid")
    else:
        print("Signature Invalid")

    print("Auditor cannot decrypt salary record")
    
# Tamper
def tamper_file():
    with open("salary.enc", "rb") as file:
        data = bytearray(file.read())

    if len(data) == 0:
        print("File is empty")
        return

    data[0] = data[0] ^ 1
    with open("salary.enc", "wb") as file:
        file.write(data)

    print("Encrypted file tampered successfully")
    
while True:
    print("1. HR Officer")
    print("2. Manager")
    print("3. Auditor")
    print("4. Tamper File")
    print("0. Exit")

    choice = int(input("Enter choice: "))

    if choice == 1:
        hr_officer()

    elif choice == 2:
        manager()

    elif choice == 3:
        auditor()

    elif choice == 4:
        tamper_file()

    elif choice == 0:
        break

    else:
        print("Invalid choice")