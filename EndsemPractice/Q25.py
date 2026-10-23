# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    SECURE GRANT EXPENSE PORTAL

    Scenario:

    A research institute manages grant expenses through an online portal. 
    Researchers submit grant details, reviewers check their integrity and authenticity, and the finance officer computes the total grant expenditure. 
    The system must keep grant data confidential and verifiable, and the total must be computed without decrypting individual amounts.

    Requirements:
    - Researcher side: The researcher enters a Grant ID, Grant Description and Grant Amount. 
    - Before storing, the system:
        - Encrypts the grant description with AES-192.
        - Encrypts the grant amount with the Paillier cryptosystem.
        - Computes an MD5 hash of the grant record.
        - Signs the hash with an RSA digital signature.
    
    - The researcher can submit grant details, and view all submitted records, including those entered earlier.
    - Reviewer side: 
        - The reviewer verifies the RSA signature and recomputes the MD5 hash to detect tampering. 
        - The reviewer can search the stored records by index (Grant ID) without exposing the encrypted contents. 
        - The reviewer can also view the AES-192 decrypted grant description as a hexadecimal dump.

    - Finance Officer side: 
        - The finance officer homomorphically aggregates the Paillier-encrypted amounts of the selected grants. 
        - The officer then verifies the signatures and decrypts only the final aggregate, never individual amounts.

    - Task:
        - Write a menu-driven Python program implementing the above roles and functions. 
        - Use role-based menus and cryptographic operations for confidentiality, integrity and authenticity. 
        - Store the encrypted, hashed and signed records persistently (file or database), so that earlier entries remain visible after a restart. 
        - Handle invalid input and tampered records gracefully. Display outputs for all functions.
    
    IT-B Question on 23/10/2026
'''

import hashlib
import os
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

FILE = "grants.txt"
records = []

# Load previous records
if os.path.exists(FILE):
    with open(FILE, "r") as f:
        for line in f:
            fields = line.strip().split("|")
            records.append({
                "id": fields[0],
                "iv": fields[1],
                "cipher": fields[2],
                "amount": int(fields[3]),
                "hash": fields[4],
                "signature": int(fields[5])
            })
            
print("Loaded records:", len(records))

while True:
    print("1. Researcher Menu")
    print("2. Reviewer Menu")
    print("3. Finance Officer Menu")
    print("0. Exit")

    choice = input("Choose role: ")
    
    if choice == "1":
        while True:
            print("\n1. Submit Grant")
            print("2. View All Grants")
            print("0. Back")

            c = input("Choice: ")
            if c == "1":
                grant_id = input("Grant ID: ")
                description = input("Description: ")
                amount = int(input("Grant amount: "))
            
                found = False
                for r in records:
                    if r["id"] == grant_id:
                        found = True
                        break 
                    
                if found == True:
                    print("Grant ID already exists")
                    continue
                
                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                encrypted_description = cipher.encrypt(pad(description.encode(), 16))
                
                encrypted_amount = pub.encrypt(amount).ciphertext()
                message = grant_id + "|" + description + "|" + str(encrypted_amount)
                message = message.encode()
                
                digest = hashlib.md5(message).digest()
                digest_hex = digest.hex()
                
                h = int.from_bytes(digest, "big") % n
                signature = pow(h, d, n)
                
                record = {
                    "id": grant_id,
                    "iv": iv.hex(),
                    "cipher": encrypted_description.hex(),
                    "amount": encrypted_amount,
                    "hash": digest_hex,
                    "signature": signature
                }
                
                records.append(record)
                
                with open(FILE, "a") as f:
                    f.write(
                        grant_id + "|" + record["iv"] + "|"
                        + record["cipher"] + "|"
                        + str(encrypted_amount) + "|"
                        + digest_hex + "|" + str(signature) + "\n"
                    )
                    
                print("Grant submitted successfully.")
                print("Encrypted description:", record["cipher"])
                print("Encrypted amount:", encrypted_amount)
                print("MD5:", digest_hex)
                print("RSA signature:", signature)
                
            elif c == "2":
                for i, r in enumerate(records):
                        print(
                            i + 1, "Grant ID:", r["id"],
                            "| Encrypted description:", r["cipher"],
                            "| Encrypted amount:", r["amount"],
                            "| MD5:", r["hash"],
                            "| Signature:", r["signature"]
                        )
                        
            elif c == "0":
                break
            else:
                print("Invalid choice")
                
    elif choice == "2":
        while True:
            print("\n1. Verify Grant")
            print("2. Search by Grant ID")
            print("3. View Description Hex Dump")
            print("0. Back")

            c = input("Choice: ")
            
            if c == "1":
                grant_id = input("Grant ID: ")
                found = False
                record = {}
                for r in records:
                    if r["id"] == grant_id:
                        found = True
                        record = r
                        break 
                    
                if found == False:
                    print("Grant not found")
                    continue
                
                cipher = AES.new(aes_key, AES.MODE_CBC, bytes.fromhex(record["iv"]))
                description = unpad(cipher.decrypt(bytes.fromhex(record["cipher"])), 16).decode()
                
                message = record["id"] + "|" + description + "|" + str(record["amount"])
                message = message.encode()
                
                digest = hashlib.md5(message).digest()
                hash_ok = digest.hex() == record["hash"]
                
                h = int.from_bytes(digest, "big") % n
                signature_ok = pow(record["signature"], e, n) == h

                print("MD5 valid:", hash_ok)
                print("RSA signature valid:", signature_ok)
                print("Grant authentic:", hash_ok and signature_ok)
                
            elif c == "2":
                grant_id = input("Grant ID to search: ")
                record = {}
                found = False
                for r in records:
                    if r["id"] == grant_id:
                        found = True
                        record = r
                        break 
                    
                if found == False:
                    print("Grant not found")
                    continue
                    
                print("Grant found")
                
            elif c == "3":
                grant_id = input("Grant ID: ")
                record = {}
                found = False
                for r in records:
                    if r["id"] == grant_id:
                        found = True
                        record = r
                        break 
                    
                if found == False:
                    print("Grant not found")
                    continue
                
                cipher = AES.new(aes_key, AES.MODE_CBC, bytes.fromhex(record["iv"]))
                description = unpad(cipher.decrypt(bytes.fromhex(record["cipher"])), 16)
                print("Description hex dump:", description.hex())
                
            elif c == "0":
                break 
            else:
                print("Invalid Choice!")
                
    elif choice == "3":
        while True:
            print("\n1. Aggregate Selected Grants")
            print("0. Back")
            
            c = input("Choice: ")
            if c == "1":
                ids = input("Enter Grant IDs separated by commas: ")
                
                selected = []
                valid = True 
                
                for grant_id in ids:
                    grant_id = grant_id.strip()
                    record = {}
                    for r in records:
                        if r["id"] == grant_id:
                            found = True
                            record = r
                            break 
                    
                    if found == False:
                        print("Grant not found")
                        valid = False
                        break 
                        
                    cipher = AES.new(aes_key, AES.MODE_CBC, bytes.fromhex(record["iv"]))
                    description = unpad(cipher.decrypt(bytes.fromhex(record["cipher"])), 16).decode()
                    
                    message = record["id"] + "|" + description + "|" + str(record["amount"])
                    message = message.encode()
                    
                    digest = hashlib.md5(message).digest()
                    h = int.from_bytes(digest, "big") % n
                    
                    if digest.hex() != record["hash"] or pow(record["signature"], e, n) != h:
                        print("Tampered: ", grant_id)
                        valid = False
                        break 
                    
                    selected.append(record)
                    
                if not valid or not selected:
                    print("Aggregation cancelled.")
                    continue
                
                total = EncryptedNumber(pub, selected[0]["amount"])
                
                for r in selected[1:]:
                    total += EncryptedNumber(pub, r["amount"])
                    
                print("Encrypted aggregate:", total.ciphertext())
                
                print("Final grant expenditure:", priv.decrypt(total))
                
            elif c == "0":
                break
            else:
                print("Invalid choice")
                
    elif choice == "0":
        print("Exiting portal.")
        break

    else:
        print("Invalid role choice")