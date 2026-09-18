# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    A bank wants to build a secure transaction-record system called SecureBank with three roles: Customer, Bank Officer, Auditor
    
    - Customer
        - The Customer should be able to:
            - Enter transaction information:
            - Account Number
            - Transaction ID
            - Amount
            - Transaction Type
            - Store the transaction information.
            - Encrypt the transaction information using the Vigenère cipher with a user-provided key.
            - Generate an RSA key pair.
            - Encrypt the Vigenère key using RSA public key.
            - Compute the SHA-256 hash of the Vigenère-encrypted transaction.
            - Store:
                - Encrypted transaction
                - RSA-encrypted Vigenère key
                - SHA-256 hash
                - Timestamp
            - View stored transactions.
    
    - Bank Officer
        - The Bank Officer should be able to:
            - View encrypted transaction records.
            - View the encrypted Vigenère key, hash and timestamp.
            - Verify the SHA-256 hash.
            - The Officer must not decrypt the transaction.
    
    - Auditor
        - The Auditor should be able to:
            - View transaction ID, hash and timestamp.
            - Verify the SHA-256 hash.
            - The Auditor must not access plaintext or encryption keys.
'''

import hashlib
from datetime import datetime

p = 61
q = 53
e = 17
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
public_key = (e, n)
private_key = (d, n)

def rsa_encrypt(value, public_key):
    e, n = public_key
    return pow(value, e, n)

records = []

def vigenere_encrypt(text, key):
    result = ""
    key = key.upper();
    key_idx = 0
    for ch in text.upper():
        if ch.isalpha():
            p = ord(ch) - ord('A')
            k = ord(key[key_idx % len(key)]) - ord('A')
            c = (p + k) % 26
            result += chr(c + ord('A'))
            key_idx += 1
            
    return result 

# Customer
def add_transactions():
    tid = input("Enter Transaction ID: ")
    account = input("Enter Account Number: ")
    amount = input("Enter Amount: ")
    transaction_type = input("Enter Transaction Type: ")
    
    data = "ID:" + tid + ",Account:" + account + ",Amount:" + amount + ",Type:" + transaction_type

    key = "SECURE"
    encrypted_data = vigenere_encrypt(data, key)
    
    key_value = int.from_bytes(key.encode())
    encrypted_key = rsa_encrypt(key_value, public_key)
    
    hash_val = hashlib.sha256(encrypted_data.encode()).hexdigest()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    record = {
        "ID": tid,
        "Encrypted Data": encrypted_data,
        "Encrypted Key": encrypted_key,
        "Hash": hash_val,
        "Timestamp": timestamp
    }
    
    records.append(record)
    print("Transaction stored successfully.")
    print("Encrypted Transaction:", encrypted_data)
    print("RSA Encrypted Key:", encrypted_key)
    print("SHA-256 Hash:", hash_val)
    print("Timestamp:", timestamp)
    
def customer_view():
    for record in records:
        print("\nTransaction ID:", record["ID"])
        print("Encrypted Data:", record["Encrypted Data"])
        print("Encrypted Key:", record["Encrypted Key"])
        print("Hash:", record["Hash"])
        print("Timestamp:", record["Timestamp"])
        
# Officer
def officer_view():
    for record in records:
        print("\nTransaction ID:", record["ID"])
        print("Encrypted Data:", record["Encrypted Data"])
        print("Encrypted Vigenere Key:", record["Encrypted Key"])
        print("SHA-256 Hash:", record["Hash"])
        print("Timestamp:", record["Timestamp"])
        
    
def officer_verify():
    tid = input("Enter Transaction ID: ")
    for record in records:
        if record["ID"] == tid:
            curr_hash = hashlib.sha256(record["Encrypted Data"].encode()).hexdigest()
            
            if curr_hash == record["Hash"]:
                print("Integrity: VALID")
            else:
                print("Integrity: INVALID")
                
            print("Verification Timestamp:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            return
        
    print("Transaction not found.")
    
# Auditor
def auditor_view():
    for record in records:
        print("\nTransaction ID:", record["ID"])
        print("SHA-256 Hash:", record["Hash"])
        print("Timestamp:", record["Timestamp"])

def auditor_verify():
    tid = input("Enter Transaction ID: ")

    for record in records:
        if record["ID"] == tid:
            current_hash = hashlib.sha256(record["Encrypted Data"].encode()).hexdigest()

            if current_hash == record["Hash"]:
                print("SHA-256 Integrity: VALID")
            else:
                print("SHA-256 Integrity: INVALID")

            return

    print("Transaction not found.")
    
while True:
    print("1. Customer")
    print("2. Bank Officer")
    print("3. Auditor")
    print("4. Exit")

    role = int(input("Enter Role: "))

    if role == 1:
        while True:
            print("1. Add Transaction")
            print("2. View Records")
            print("3. Back")

            choice = int(input("Enter choice: "))

            if choice == 1:
                add_transactions()

            elif choice == 2:
                customer_view()

            elif choice == 3:
                break

            else:
                print("Invalid choice.")

    elif role == 2:
        while True:
            print("1. View Encrypted Records")
            print("2. Verify Integrity")
            print("3. Back")

            choice = int(input("Enter choice: "))

            if choice == 1:
                officer_view()

            elif choice == 2:
                officer_verify()

            elif choice == 3:
                break

            else:
                print("Invalid choice.")

    elif role == 3:
        while True:
            print("1. View Records")
            print("2. Verify Integrity")
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
        print("Exiting SecureBank...")
        break

    else:
        print("Invalid role.")