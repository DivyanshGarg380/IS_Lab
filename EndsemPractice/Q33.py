# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    An insurance company stores claims containing a claim ID, description, and requested compensation amount.
    - Claims Officer: Submit claims. Encrypt the description using AES-CBC, encrypt the amount using Paillier, generate HMAC-SHA256 tokens for searchable keywords, and calculate a SHA-256 hash of the encrypted description.
    - Investigator: Search claims by keyword without decrypting descriptions. Display matching claim IDs and claim statuses.
    - Manager: Mark claims as APPROVED or REJECTED.
    - Finance Officer: Aggregate the encrypted compensation amounts of selected approved claims. Decrypt only the final sum.
    - Auditor: Verify the encrypted-description hash before aggregation.
'''

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib
import hmac
from phe import paillier

key = b"123456789012345678901234"
iv = b"1234567890123456"
search_key = b"insurance-search-key"

public_key, private_key = paillier.generate_paillier_keypair()
claims = []

while True:
    print("\n1. Claims Officer")
    print("2. Investigator")
    print("3. Manager")
    print("4. Finance Officer")
    print("5. Auditor")
    print("6. Exit")

    role = input("Choose role: ")

    if role == "1":
        cid = input("Claim ID: ")
        found = False
        for c in claims:
            if c["id"] == cid:
                found = True
                break
            
        if found:
            print("Duplicate claim ID")
            continue

        description = input("Claim description: ")
        amount = int(input("Compensation amount: "))
        if amount <= 0:
            print("Amount must be positive")
            continue
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_description = cipher.encrypt(pad(description.encode(), AES.block_size))
        
        encrypted_amount = public_key.encrypt(amount)

        digest = hashlib.sha256(encrypted_description).hexdigest()
        
        tokens = []
        for word in description.lower().split():
            token = hmac.new(search_key, word.encode(), hashlib.sha256).hexdigest()
            
            if token not in tokens:
                tokens.append(token)
                
        claims.append({
            "id": cid,
            "encrypted_description": encrypted_description,
            "encrypted_amount": encrypted_amount,
            "hash": digest,
            "tokens": tokens,
            "status": "PENDING",
            "verified": False
        })
        
        print("Claim submitted securely")
        
    elif role == "2":
        keyword = input("Search keyword: ").lower()
        
        search_token = hmac.new(search_key, keyword.encode(), hashlib.sha256).hexdigest()
        
        found = False
        for c in claims:
            if search_token in c["tokens"]:
                print("Claim ID:", c["id"])
                print("Status:", c["status"])
                found = True

        if not found:
            print("No matching claims")
            
    elif role == "3":
        cid = input("Claim ID: ")
        found = False

        for c in claims:
            if c["id"] == cid:
                found = True
                
                if c["status"] != "PENDING":
                    print("Claim already processed")
                    break 
                
                decision = input("Approve or reject? ").lower()
                
                if decision == "approve":
                    c["status"] = "APPROVED"
                    print("Claim approved")
                    
                elif decision == "reject":
                    c["status"] = "REJECTED"
                    print("Claim rejected")
                    
                else:
                    print("Invalid decision")
                    
                break
            
        if not found:
            print("Claim not found")
            
    elif role == "4":
        selected = input("Enter approved claim ID's seperated by spaces: ").split()
        encrypted_total = None 
        valid = True 
        seen = []
        
        for cid in selected:
            if cid in seen:
                print("Duplicate claim ID:", cid)
                valid = False
                break   
            
            seen.append(cid)
            found = False 
            
            for c in claims:
                if c["id"] == cid:
                    found = True
                    actual_hash = hashlib.sha256(c["encrypted_description"]).hexdigest()
                    if c["status"] != "APPROVED":
                        print(cid, "is not approved")
                        valid = False 

                    elif actual_hash != c["hash"]:
                        print(cid, "failed integrity check")
                        valid = False 
                        
                    elif not c["verified"]:
                        print(cid, "has not been audited")
                        valid = False

                    else:
                        if encrypted_total is None:
                            encrypted_total = c["encrypted_amount"]
                            
                        else:
                            encrypted_total += c["encrypted_amount"]
                            
                    break 
                
            if not found:
                print("Claim not found:", cid)
                valid = False
                
        if valid and encrypted_total is not None:
            total = private_key.decrypt(encrypted_total)
            print("Final encrypted aggregate decrypted:", total)
        else:
            print("Aggregation denied")

    elif role == "5":
        cid = input("Claim ID to audit: ")
        found = False

        for c in claims:
            if c["id"] == cid:
                found = True

                actual_hash = hashlib.sha256(c["encrypted_description"]).hexdigest()

                if actual_hash == c["hash"]:
                    c["verified"] = True
                    print("Integrity verified")
                else:
                    c["verified"] = False
                    print("Tampering detected")

                break

        if not found:
            print("Claim not found")

    elif role == "6":
        break

    else:
        print("Invalid role")
