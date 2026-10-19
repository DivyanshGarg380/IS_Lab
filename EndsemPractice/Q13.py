# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    A hospital maintains encrypted clinical reports.
    Implement a menu-driven system with three roles: Doctor, Auditor, and Admin.
        - Doctor: encrypt a report using AES-128-CBC, calculate its SHA-256 hash, and create a textbook RSA signature on the hash integer.
        - Auditor: verify the hash and RSA signature without decrypting the report.
        - Admin: view only the ciphertext in hexadecimal, IV, hash and signature; must not access plaintext or decrypt.
    
    The ciphertext and IV must be converted to hexadecimal for storage in memory and converted back to bytes when required.
    If integrity or signature verification fails, the Auditor must reject the record.
'''

import hashlib
import math
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

p,q,e = 61,53,17
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

def hash_bytes(data):
    return hashlib.sha256(data).digest()

def hash_integer(data):
    return int.from_bytes(hash_bytes(data), "big") % n

records = {}
aes_key = get_random_bytes(16)

def create_record():
    report = input("Enter clinical report: ")
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(report.encode(), 16))
    
    ciphertext_hex = ciphertext.hex()
    iv_hex = iv.hex()
    
    digest = hash_integer(ciphertext)
    signature = pow(digest, d, n)
    record_id = str(len(records) + 1)
    records[record_id] = {
        "ciphertext": ciphertext_hex,
        "iv": iv_hex,
        "hash": hashlib.sha256(ciphertext).hexdigest(),
        "signature": signature
    }
    
    print("Record stored in memory. ID:", record_id)
    print("Ciphertext (hex):", ciphertext_hex)
    print("IV (hex):", iv_hex)
    print("SHA-256 (hex):", records[record_id]["hash"])
    print("RSA signature:", signature)

def audit_record():
    record_id = input("Enter record ID: ")

    if record_id not in records:
        print("Record not found!")
        return
    
    record = records[record_id]
    ciphertext = bytes.fromhex(record["ciphertext"])
    
    curr_hash = hashlib.sha256(ciphertext).hexdigest()
    hash_valid = curr_hash == record["hash"]
    
    digest = hash_integer(ciphertext)
    verified_digest = pow(record["signature"], e, n)
    signature_valid = digest == verified_digest
    
    print("Hash verification:", "VALID" if hash_valid else "INVALID")
    print("Signature verification:", "VALID" if signature_valid else "INVALID")

    if hash_valid and signature_valid:
        print("Record integrity and signature verified.")
    else:
        print("Record rejected!")
        
def admin_view():
    record_id = input("Enter record ID: ")

    if record_id not in records:
        print("Record not found!")
        return

    record = records[record_id]

    print("Ciphertext (hex):", record["ciphertext"])
    print("IV (hex):", record["iv"])
    print("SHA-256:", record["hash"])
    print("Signature:", record["signature"])
    print("Admin cannot decrypt or view plaintext.")

def doctor_decrypt():
    record_id = input("Enter record ID: ")

    if record_id not in records:
        print("Record not found!")
        return

    record = records[record_id]
    ciphertext = bytes.fromhex(record["ciphertext"])
    iv = bytes.fromhex(record["iv"])

    hash_valid = hashlib.sha256(ciphertext).hexdigest() == record["hash"]

    signature_valid = pow(record["signature"], e, n) == hash_integer(ciphertext)

    if not (hash_valid and signature_valid):
        print("Verification failed! Decryption denied.")
        return

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    try:
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
        print("Clinical report:", plaintext)
    except ValueError:
        print("Decryption failed!")

while True:
    print("\n1. Doctor")
    print("2. Auditor")
    print("3. Admin")
    print("4. Exit")

    role_choice = input("Choose role: ")

    if role_choice == "1":
        while True:
            print("\nDoctor Menu: 1.Create 2.Decrypt 3.Back")
            choice = input("Choice: ")

            if choice == "1":
                create_record()
            elif choice == "2":
                doctor_decrypt()
            elif choice == "3":
                break
            else:
                print("Invalid choice!")

    elif role_choice == "2":
        while True:
            print("\nAuditor Menu: 1.Verify 2.Back")
            choice = input("Choice: ")

            if choice == "1":
                audit_record()
            elif choice == "2":
                break
            else:
                print("Invalid choice!")

    elif role_choice == "3":
        while True:
            print("\nAdmin Menu: 1.View Metadata 2.Back")
            choice = input("Choice: ")

            if choice == "1":
                admin_view()
            elif choice == "2":
                break
            else:
                print("Invalid choice!")

    elif role_choice == "4":
        break

    else:
        print("Invalid role!")
