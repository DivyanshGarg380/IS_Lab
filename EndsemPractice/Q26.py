# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    A university allows researchers to submit research papers to a review server.

    Requirements
    - Researcher: enter Paper ID and paper text. Encrypt the text using AES-192-CBC, calculate SHA-256, and sign the hash using RSA.
    - Reviewer: verify the hash and RSA signature, search papers by Paper ID, and display decrypted paper text as hexadecimal.
    - Admin: simulate tampering with a stored paper.
    - Use a menu-driven program with role-based access.
    - Store records in memory only; no files.
'''

import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

aes_key = b"123456789012345678901234"
iv = b"1234567890123456"

p, q, e = 61, 53, 17
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

records = []

while True:
    print("\n1. Researcher")
    print("2. Reviewer")
    print("3. Admin")
    print("0. Exit")

    role = input("Choose role: ")
    if role == "1":
        while True:
            print("\n1. Submit Paper")
            print("2. View Papers")
            print("0. Back")
            choice = input("Choice: ")
            
            if choice == "1":
                paper_id = input("Paper ID: ")
                text = input("Paper text: ")
                
                data = text.encode()
                
                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                encrypted = cipher.encrypt(pad(data, 16))
                digest = hashlib.sha256(data).digest()
                
                h = int.from_bytes(digest, "big") % n
                signature = pow(h, d, n)
                
                records.append({
                    "id": paper_id,
                    "cipher": encrypted.hex(),
                    "hash": digest.hex(),
                    "signature": signature
                })
                
                print("Paper submitted.")
                print("Encrypted text:", encrypted.hex())
                print("SHA-256:", digest.hex())
                print("RSA signature:", signature)
                
            elif choice == "2":
                for r in records:
                    print(
                        "ID:", r["id"],
                        "Ciphertext:", r["cipher"],
                        "Hash:", r["hash"],
                        "Signature:", r["signature"]
                    )

            elif choice == "0":
                break 
            
    elif role == "2":
        while True:
            print("\n1. Verify Paper")
            print("2. Search Paper")
            print("3. Hex Dump")
            print("0. Back")
            choice = input("Choice: ")

            if choice == "1":
                paper_id = input("Paper ID: ")
                record = None
                
                for r in records:
                    if r["id"] == paper_id:
                        record = r
                        break 
                    
                if record is None:
                    print("Paper not found")
                    continue
                
                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                data = unpad(cipher.decrypt(bytes.fromhex(record["cipher"])), 16)
                
                digest = hashlib.sha256(data).digest()
                hash_ok = digest.hex() == record["hash"]
                
                h = int.from_bytes(digest, "big") % n
                signature_ok = pow(record["signature"], e, n) == h 
                print("Hash valid:", hash_ok)
                print("Signature valid:", signature_ok)
                print("Paper authentic:", hash_ok and signature_ok)
                
            elif choice == "2":
                paper_id = input("Search Paper ID: ")
                found = False
                
                for i, r in enumerate(records):
                    if r["id"] == paper_id:
                        print("Found at index:", i)
                        print("Encrypted paper:", r["cipher"])
                        found = True
                        
                if not found:
                    print("Paper not found")
                    
            elif choice == "3":
                paper_id = input("Paper ID: ")
                record = None

                for r in records:
                    if r["id"] == paper_id:
                        record = r
                        break

                if record is None:
                    print("Paper not found")
                    continue
                
                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                data = unpad(cipher.decrypt(bytes.fromhex(record["cipher"])), 16)
                
                print("Hex Dump: ", data.hex())
            
            elif choice == "0":
                break 
            
    elif role == "3":
        paper_id = input("Paper ID to tamper with: ")
        
        for r in records:
            if r["id"] == paper_id:
                encrypted = bytearray(bytes.fromhex(r["cipher"]))
                encrypted[0] ^= 1
                r["cipher"] = bytes(encrypted).hex()
                print("Paper Tampered!")
                break 
            
    elif role == "0":
        break