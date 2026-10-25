# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    A hospital stores encrypted medical bills and must calculate total bills without decrypting each individual amount.

    Requirements
    - Clerk: enter Patient ID, department and bill amount.
    - Encrypt the department description using AES-192-CBC.
    - Encrypt the bill amount using Paillier.
    - Calculate MD5 over the record and sign it using RSA.
    - Auditor: verify integrity and signature, search by Patient ID, and show the decrypted department description as hexadecimal.
    - Finance: select patient IDs, verify each record, homomorphically add encrypted bills, and decrypt only the aggregate.
    - Menu-driven RBAC; in-memory storage only.
'''

import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from phe import PaillierPublicKey, PaillierPrivateKey, EncryptedNumber

aes_key = b"123456789012345678901234"
iv = b"1234567890123456"

p, q, e = 61, 53, 17
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

pp, pq = 1009, 1013
pn = pp * pq
pub = PaillierPublicKey(pn)
priv = PaillierPrivateKey(pub, pp, pq)

records = []

while True:
    print("\n1. Clerk")
    print("2. Auditor")
    print("3. Finance")
    print("0. Exit")
    role = input("Choose role: ")
    
    if role == "1":
        while True:
            print("\n1. Add Bill")
            print("2. View Bills")
            print("0. Back")
            choice = input("Choice: ")

            if choice == "1":
                patient = input("Patient ID: ")
                department = input("Department: ")
                amount = int(input("Bill amount: "))
                
                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                encrypted = cipher.encrypt(pad(department.encode(), AES.block_size))
                encrypted_amount = pub.encrypt(amount).ciphertext()
                
                
                message = patient + "|" + department + "|" + str(encrypted_amount)
                message = message.encode()
                
                digest = hashlib.md5(message).digest()
                h = int.from_bytes(digest, "big") % n
                signature = pow(h, d, n)
                
                records.append({
                    "patient": patient,
                    "cipher": encrypted.hex(),
                    "amount": encrypted_amount,
                    "hash": digest.hex(),
                    "signature": signature
                })
                
                print("Bill stored.")
                print("Encrypted department:", encrypted.hex())
                print("Encrypted amount:", encrypted_amount)
                print("MD5:", digest.hex())
                print("Signature:", signature)
            
            elif choice == "2":
                for r in records:
                    print(
                        r["patient"], r["cipher"],
                        r["amount"], r["hash"], r["signature"]
                    )
                    
            elif choice == "0":
                break 
            
    elif role == "2":
        while True:
            print("\n1. Verify Bill")
            print("2. Search Patient")
            print("3. Department Hex Dump")
            print("0. Back")
            choice = input("Choice: ")
            
            if choice == "1":
                patient = input("Patient ID: ")
                record = None 
                
                for r in records:
                    if r["patient"] == patient:
                        record = r
                        break
                    
                if record is None:
                    print("Patient not found")
                    continue

                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                department = unpad(cipher.decrypt(bytes.fromhex(record["cipher"])), AES.block_size).decode()
                
                message = patient + "|" + department + "|" + str(record["amount"])
                message = message.encode()
                
                digest = hashlib.md5(message).digest()
                hash_ok = digest.hex() == record["hash"]

                h = int.from_bytes(digest, "big") % n
                signature_ok = pow(record["signature"], e, n) == h 
                
                print("MD5 valid:", hash_ok)
                print("Signature valid:", signature_ok)
                
            elif choice == "2":
                patient = input("Patient ID: ")
                for i, r in enumerate(records):
                    if r["patient"] == patient:
                        print("Index:", i)
                        print("Encrypted department:", r["cipher"])
                        
            elif choice == "3":
                patient = input("Patient ID: ")
                record = None

                for r in records:
                    if r["patient"] == patient:
                        record = r
                        break

                if record is None:
                    print("Patient not found")
                    continue

                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                department = unpad(cipher.decrypt(bytes.fromhex(record["cipher"])), AES.block_size)

                print("Department hex:", department.hex())

            elif choice == "0":
                break
            
    elif role == "3":
        ids = input("Patient IDs separated by commas: ").split(",")
        selected = []
        valid = True
        
        for patient in ids:
            patient = patient.strip()
            record = None 
            for r in records:
                if r["patient"] == patient:
                    record = r
                    break
            
            if record is None:
                print("Patient not found:", patient)
                valid = False
                break
            
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            department = unpad(cipher.decrypt(bytes.fromhex(record["cipher"])), AES.block_size).decode()
            message = patient + "|" + department + "|" + str(record["amount"])
            message = message.encode()
            
            digest = hashlib.md5(message).digest()
            h = int.from_bytes(digest, "big") % n
            
            if(digest.hex() != record["hash"] or pow(record["signature"], e, n) != h):
                print("Tampered record:", patient)
                valid = False
                break
            
            selected.append(record)
            
        if not valid or not selected:
            print("Aggregation cancelled")
            continue

        total = EncryptedNumber(pub, selected[0]["amount"])
        
        for r in selected[1:]:
            total += EncryptedNumber(pub, r["amount"])

        print("Encrypted aggregate:", total.ciphertext())
        print("Final total bill:", priv.decrypt(total))
        
    elif role == "0":
        break