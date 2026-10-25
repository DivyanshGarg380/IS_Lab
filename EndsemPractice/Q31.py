# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    A university procurement system stores purchase requests. Each request contains:
        - Request ID
        - Department
        - Description
        - Bill amount
    
    - Implement a menu-driven Python program with these roles:

    1. Employee
        - Submit a purchase request.
        - Encrypt the description using AES-192-CBC.
        - Encrypt the bill amount using Paillier.
        - Generate HMAC-SHA256 keyword tokens from the description for SSE searching.
        - Calculate a SHA-256 hash of the encrypted description.
    2. Reviewer
        - Search requests by a keyword without decrypting descriptions.
        - Display matching request IDs and departments.
        - Approve or reject a request.
    3. Finance Officer
        - Select approved requests by their IDs.
        - Add their Paillier ciphertexts homomorphically.
        - Decrypt only the final aggregate amount, not the individual bills.
    4. Auditor

    - Verify the encrypted-description hash before a request is allowed into financial aggregation.
'''

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib
import hmac
from phe import paillier

key = b"123456789012345678901234"
iv = b"1234567890123456"
search_key = b"procurement-search-key"

public_key, private_key = paillier.generate_paillier_keypairs()
requests = []

while True:
    print("\n1. Employee")
    print("2. Reviewer")
    print("3. Finance Officer")
    print("4. Auditor")
    print("5. Exit")

    role = input("Choose role: ")

    if role == "1":
        rid = input("Request ID: ")
        found = False
        for r in requests:
            if r["id"] == rid:
                found = True
                break

        if found:
            print("Duplicate request ID")
            continue
        
        department = input("Department: ")
        description = input("Description: ")

        amount = int(input("Bill amount: "))
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
                
        requests.append({
            "id": rid,
            "department": department,
            "encrypted_description": encrypted_description,
            "encrypted_amount": encrypted_amount,
            "hash": digest,
            "tokens": tokens,
            "status": "PENDING",
            "verified": False
        })
        
        print("Request submitted securely")
        
    elif role == "2":
        print("\n1. Search by keyword")
        print("2. Approve or reject request")
        action = input("Choose: ")

        if action == "1":
            keyword = input("Keyword: ").lower()
            token = hmac.new(search_key, keyword.encode(), hashlib.sha256).hexdigest()
            
            found = False 
            for r in requests:
                if token in r["tokens"]:
                    print("Request ID:", r["id"])
                    print("Department:", r["department"])
                    print("Status:", r["status"])
                    found = True
            
            if not found:
                print("No matching requests")
                
        elif action == "2":
            rid = input("Request ID: ")
            found = False   
            for r in requests:
                if r["id"] == rid:
                    found = True
                    choice = input("Approve or reject? ").lower()

                    if choice == "approve":
                        r["status"] = "APPROVED"
                        print("Request approved")
                    elif choice == "reject":
                        r["status"] = "REJECTED"
                        print("Request rejected")
                    else:
                        print("Invalid action")

                    break

            if not found:
                print("Request not found")
                
    elif role == "3":
        selected= input("Enter approved request IDs seperated by spaced: ").split()
        encrypted_total = None
        found_any = False
        valid = True
        
        for rid in selected:
            matched = False
            
            for r in requests:
                if r["id"] == rid:
                    matched = True
                    actual_hash = hashlib.sha256(r["encrypted_description"]).hexdigest()

                    if r["status"] != "APPROVED":
                        print(rid, "is not approved")
                        valid = False

                    elif actual_hash != r["hash"]:
                        print(rid, "failed integrity check")
                        valid = False

                    elif not r["verified"]:
                        print(rid, "has not been audited")
                        valid = False

                    else:
                        if encrypted_total is None:
                            encrypted_total = r["encrypted_amount"]
                        else:
                            encrypted_total += r["encrypted_amount"]

                        found_any = True

                    break

            if not matched:
                print("Request not found:", rid)
                valid = False

        if valid and found_any:
            total = private_key.decrypt(encrypted_total)
            print("Final aggregate amount:", total)
        else:
            print("Aggregation denied")

    elif role == "4":
        rid = input("Request ID to audit: ")
        found = False

        for r in requests:
            if r["id"] == rid:
                found = True
                actual_hash = hashlib.sha256(r["encrypted_description"]).hexdigest()
                if actual_hash == r["hash"]:
                    r["verified"] = True
                    print("Integrity verified")
                else:
                    r["verified"] = False
                    print("Tampering detected")

                break

        if not found:
            print("Request not found")

    elif role == "5":
        break

    else:
        print("Invalid role")
