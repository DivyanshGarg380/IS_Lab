# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    - A hospital stores patient reports securely. 
    - The system must hash reports using SHA-256, encrypt them using DES-CBC, encrypt a numeric report code using RSA, sign the hash using ElGamal, and use Paillier to calculate the aggregate of encrypted report scores. 
    - Implement a menu-driven program with basic RBAC and searchable encryption to locate reports by department.
'''

import hashlib
import hmac
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from phe import paillier

des_key = b"8bytekey"
iv = b"12345678"

p,q,e = 11,13,7
n = p*q
phi = (p-1)*(q-1)
d = pow(e, -1, phi)

gp,g,x,k = 467,2,127,53
y = pow(g, x, gp)

pub, priv = paillier.generate_paillier_keypair()

reports = []
search_key = b"hospital-search-key"
scores = []

while True:
    print("\n1. Add Report")
    print("2. Verify and Decrypt Report")
    print("3. Calculate Aggregate Score")
    print("4. Search by Department")
    print("0. Exit")

    choice = input("Choice: ")
    role = input("Role (Doctor/Admin/Auditor): ")
    
    if choice == "1":
        if role != "Doctor":
            print("Access denied")
            continue
        
        patient = input("Patient ID: ")
        department = input("Department: ")
        report = input("Report text: ")
        score = int(input("Numeric score: "))
        
        data = report.encode()
        digest = hashlib.sha256(data).digest()
        
        cipher = DES.new(des_key, DES.MODE_CBC, iv)
        encrypted_report = cipher.encrypt(pad(data, 8))
        
        H = int.from_bytes(digest, "big") % (gp - 1)
        r = pow(g, k, gp)
        s = (pow(k, -1, gp - 1) * (H - x * r)) % (gp - 1)
        
        encrypted_code = pow(score % n, e, n)
        encrypted_score = pub.encrypt(score)
        
        token = hmac.new(search_key, department.encode(), hashlib.sha256).hexdigest()
        
        reports.append({
            "patient": patient,
            "department": department,
            "token": token,
            "ciphertext": encrypted_report,
            "hash": digest.hex(),
            "signature": (r, s),
            "code": encrypted_code,
            "score": encrypted_score
        })
        
        print("Report stored.")
        print("SHA-256:", digest.hex())
        print("RSA-encrypted score code:", encrypted_code)
        print("ElGamal signature:", (r, s))
        
    elif choice == "2":
        if role not in ["Doctor", "Admin"]:
            print("Access denied")
            continue
        
        idx = int(input("Report number (starting at 1): ")) - 1
        rec = reports[idx]
        
        cipher = DES.new(des_key, DES.MODE_CBC, iv)
        data = unpad(cipher.decrypt(rec["ciphertext"]), 8)
        digest = hashlib.sha256(data).digest()
        
        H = int.from_bytes(digest, "big") % (gp - 1)
        r, s = rec["signature"]
        valid = (pow(g, H, gp) == (pow(y, r, gp) * pow(r, s, gp)) % gp)
        
        print("Hash matches:", hmac.compare_digest(digest.hex(), rec["hash"]))
        print("Signature valid:", valid)
        print("Decrypted report:", data.decode())
            
    elif choice == "3":
        if role != "Admin":
            print("Access denied")
            continue
        
        total = reports[0]["score"]
        for rec in reports[1:]:
            total = total + rec["score"]

        print("Encrypted aggregate:", total.ciphertext())
        print("Decrypted aggregate score:", priv.decrypt(total))
        
    elif choice == "4":
        if role not in ["Doctor", "Auditor", "Admin"]:
            print("Access denied")
            continue

        department = input("Department to search: ")
        query = hmac.new(search_key, department.encode(), hashlib.sha256).hexdigest()
            
        found = False
        for i, rec in enumerate(reports):
            if hmac.compare_digest(query, rec["token"]):
                print("Matching report number:", i + 1)
                found = True
                
        if not found:
            print("No matching reports")
            
    elif choice == "0":
        break
    
    else:
        print("Invalid choice")
