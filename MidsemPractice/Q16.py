# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    BankSecure — Vigenère + DES-CBC + SHA-256 + RSA Signature + RBAC

    - Roles: Employee, Manager, Auditor

    - Employee: enter transaction details → Vigenère encrypt → DES-CBC encrypt → store ciphertext in transaction.enc → SHA-256 of DES ciphertext → RSA-sign hash → store hash/signature/timestamp.
    - Manager: verify SHA-256 + RSA signature → DES decrypt → Vigenère decrypt → display original transaction.
    - Auditor: view ciphertext + hash + signature + timestamp → verify integrity and signature → cannot decrypt.
    - Employee: tamper-test encrypted file.
    - Use files + RBAC.
'''

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import hashlib
from datetime import datetime

VIG_KEY = "BANK"

def vigenere_encrypt(text):
    result = ""
    j = 0

    for ch in text.upper():
        if ch.isalpha():
            p = ord(ch) - ord('A')
            k = ord(VIG_KEY[j % len(VIG_KEY)]) - ord('A')
            result += chr((p + k) % 26 + ord('A'))
            j += 1

        else:
            result += ch

    return result

def vigenere_decrypt(text):
    result = ""
    j = 0

    for ch in text:
        if ch.isalpha():
            c = ord(ch) - ord('A')
            k = ord(VIG_KEY[j % len(VIG_KEY)]) - ord('A')
            result += chr((c - k) % 26 + ord('A'))
            j += 1

        else:
            result += ch

    return result

DES_KEY = b"A1B2C3D4"
IV = b"12345678"

def des_encrypt(text):
    cipher = DES.new(DES_KEY, DES.MODE_CBC, IV)
    return cipher.encrypt(pad(text.encode(), DES.block_size))

def des_decrypt(ciphertext):
    cipher = DES.new(DES_KEY, DES.MODE_CBC, IV)
    return unpad(cipher.decrypt(ciphertext), DES.block_size).decode()

p = 61
q = 53
e = 17
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

cipher_file = "transaction.enc"
metadata_file = "transaction.meta"

def sign_hash(hash_value):
    h = int(hash_value, 16) % n
    return pow(h, d, n)

def verify_signature(hash_value, signature):
    h = int(hash_value, 16) % n
    return pow(signature, e, n) == h

# Employee
def create_transaction():
    transaction_id = input("Enter Transaction ID: ")
    account = input("Enter Account Number: ")
    amount = input("Enter Amount: ")
    description = input("Enter Description: ")

    plaintext = "ID:" + transaction_id + ";ACCOUNT:" + account + ";AMOUNT:" + amount + ";DESC:" + description

    vigenere_cipher = vigenere_encrypt(plaintext)

    des_cipher = des_encrypt(vigenere_cipher)

    hash_value = hashlib.sha256(des_cipher).hexdigest()

    signature = sign_hash(hash_value)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open(cipher_file, "wb") as file:
        file.write(des_cipher)

    with open(metadata_file, "w") as file:
        file.write(transaction_id + "\n")
        file.write(hash_value + "\n")
        file.write(str(signature) + "\n")
        file.write(timestamp + "\n")

    print("Transaction stored successfully.")
    print("Vigenere Cipher:", vigenere_cipher)
    print("DES Cipher:", des_cipher.hex())
    print("SHA-256:", hash_value)
    print("RSA Signature:", signature)
    print("Timestamp:", timestamp)
    
# Manager View
def manager_view():
    try:
        with open(cipher_file, "rb") as file:
            ciphertext = file.read()

        with open(metadata_file, "r") as file:
            transaction_id = file.readline().strip()
            hash_value = file.readline().strip()
            signature = file.readline().strip()
            timestamp = file.readline().strip()

        print("Transaction ID:", transaction_id)
        print("Encrypted Data:", ciphertext.hex())
        print("SHA-256:", hash_value)
        print("RSA Signature:", signature)
        print("Timestamp:", timestamp)

    except FileNotFoundError:
        print("Required files not found.")
        
def manager_decrypt():
    try:
        with open(cipher_file, "rb") as file:
            ciphertext = file.read()

        with open(metadata_file, "r") as file:
            transaction_id = file.readline().strip()
            stored_hash = file.readline().strip()
            signature = int(file.readline().strip())

    except FileNotFoundError:
        print("Required files not found.")
        return

    current_hash = hashlib.sha256(ciphertext).hexdigest()

    if current_hash == stored_hash:
        print("Integrity: VALID")
    else:
        print("Integrity: INVALID")
        print("Decryption denied.")
        return
    
    if verify_signature(current_hash, signature):
        print("RSA Signature: VALID")
    else:
        print("RSA Signature: INVALID")
        print("Decryption denied.")
        return

    vigenere_cipher = des_decrypt(ciphertext)

    plaintext = vigenere_decrypt(vigenere_cipher)

    print("Transaction ID:", transaction_id)
    print("Vigenere Cipher:", vigenere_cipher)
    print("Original Transaction:", plaintext)
    
# Audtior
def auditor_view():
    try:
        with open(cipher_file, "rb") as file:
            ciphertext = file.read()

        with open(metadata_file, "r") as file:
            transaction_id = file.readline().strip()
            hash_value = file.readline().strip()
            signature = file.readline().strip()
            timestamp = file.readline().strip()

        print("Transaction ID:", transaction_id)
        print("Encrypted Data:", ciphertext.hex())
        print("SHA-256:", hash_value)
        print("RSA Signature:", signature)
        print("Timestamp:", timestamp)

    except FileNotFoundError:
        print("Required files not found.")
        
        
def auditor_verify():
    try:
        with open(cipher_file, "rb") as file:
            ciphertext = file.read()

        with open(metadata_file, "r") as file:
            transaction_id = file.readline().strip()
            stored_hash = file.readline().strip()
            signature = int(file.readline().strip())

    except FileNotFoundError:
        print("Required files not found.")
        return

    current_hash = hashlib.sha256(ciphertext).hexdigest()

    if current_hash == stored_hash:
        print("SHA-256 Integrity: VALID")
    else:
        print("SHA-256 Integrity: INVALID")

    if verify_signature(current_hash, signature):
        print("RSA Signature: VALID")
    else:
        print("RSA Signature: INVALID")
        
# Tamper
def tamper_file():
    try:
        with open(cipher_file, "rb") as file:
            data = bytearray(file.read())

        data[0] ^= 1
        with open(cipher_file, "wb") as file:
            file.write(data)

        print("Encrypted transaction modified.")
        
    except FileNotFoundError:
        print("Encrypted file not found.")


while True:
    print("1. Employee")
    print("2. Manager")
    print("3. Auditor")
    print("4. Exit")

    role = int(input("Enter Role: "))

    if role == 1:
        while True:
            print("1. Create Transaction")
            print("2. Tamper Test")
            print("3. Back")

            choice = int(input("Enter choice: "))

            if choice == 1:
                create_transaction()

            elif choice == 2:
                tamper_file()

            elif choice == 3:
                break

            else:
                print("Invalid choice.")


    elif role == 2:
        while True:
            print("1. View Transactions")
            print("2. Verify and Decrypt")
            print("3. Back")

            choice = int(input("Enter choice: "))

            if choice == 1:
                manager_view()

            elif choice == 2:
                manager_decrypt()

            elif choice == 3:
                break

            else:
                print("Invalid choice.")

    elif role == 3:
        while True:
            print("1. View Security Information")
            print("2. Verify Transaction")
            print("3. Back")

            choice = int(input("Enter choice: "))

            if choice == 1:
                auditor_view()

            elif choice == 2:
                auditor_verify()

            elif choice == 3:
                break

            else:
                print("Invalid choice.")

    elif role == 4:
        print("Exiting...")
        break

    else:
        print("Invalid role.")