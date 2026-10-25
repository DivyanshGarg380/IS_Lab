# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    A disaster relief agency tracks aid requests containing a request ID, region, description, and requested amount.
    - Relief Officer: Submit requests. Encrypt descriptions using AES-CBC, encrypt amounts using Paillier, generate HMAC-SHA256 keyword tokens for SSE, and digitally sign the request metadata using manually implemented RSA.
    - Search Officer: Search by a keyword in descriptions without decrypting them. Return matching request IDs and regions.
    - Auditor: Verify the RSA signature and SHA-256 integrity before a request can be used for financial aggregation.
    - Finance Officer: Select audited, approved requests and calculate their total using Paillier homomorphic addition. Decrypt only the final total.
    - Administrator: Approve or reject requests.
'''

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib
import hmac
from phe import paillier

key = b"123456789012345678901234"
iv = b"1234567890123456"
search_key = b"relief-search-key"

p, q, e = 61, 53, 17
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

public_key, private_key = paillier.generate_paillier_keypair()
requests = []

while True:
    print("\n1. Relief Officer")
    print("2. Search Officer")
    print("3. Auditor")
    print("4. Finance Officer")
    print("5. Administrator")
    print("6. Exit")

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

        region = input("Region: ")
        description = input("Description: ")
        
        amount = int(input("Requested amount: "))
        if amount <= 0:
            print("Amount must be positive")
            continue
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_description = cipher.encrypt(pad(description.encode(), AES.block_size))

        encrypted_amount = public_key.encrypt(amount)
        amount_ciphertext = encrypted_amount.ciphertext()
            
        digest = hashlib.sha256(encrypted_description).hexdigest()
        tokens = []
        for word in description.lower().split():
            token = hmac.new(search_key, word.encode(), hashlib.sha256).hexdigest()
            if token not in tokens:
                tokens.append(token)
                
        message = rid + "|" + region + "|" + digest + "|" + str(amount_ciphertext)
        message = message.encode()
        
        hash_value = int.from_bytes(hashlib.sha256(message).digest(), "big") % n 
        
        signature = pow(hash_value, d, n)
        requests.append({
            "id": rid,
            "region": region,
            "description": encrypted_description,
            "amount": encrypted_amount,
            "hash": digest,
            "tokens": tokens,
            "signature": signature,
            "status": "PENDING",
            "audited": False
        })

        print("Request encrypted and signed")
        
    elif role == "2":
        keyword = input("Search keyword: ").lower()
        
        search_token = hmac.new(search_key, keyword.encode(), hashlib.sha256).hexdigest()
        found = False 
        for r in requests:
            if (search_token in r["tokens"] and r["status"] != "REJECTED"):
                print("Request ID:", r["id"])
                print("Region:", r["region"])
                print("Status:", r["status"])
                found = True
                
        if not found:
            print("No matching requests")

    elif role == "3":
        rid = input("Request ID to audit: ")
        found = False

        for r in requests:
            if r["id"] == rid:
                found = True

                actual_hash = hashlib.sha256(r["description"]).hexdigest()

                message = (
                    r["id"] + "|" + r["region"] + "|" +
                    r["hash"] + "|" +
                    str(r["amount"].ciphertext())
                ).encode()

                hash_value = int.from_bytes(hashlib.sha256(message).digest(), "big") % n

                signature_valid = (pow(r["signature"], e, n) == hash_value)

                if (actual_hash == r["hash"] and signature_valid):
                    r["audited"] = True
                    print("Integrity and RSA signature verified")
                else:
                    r["audited"] = False
                    print("Tampering detected")

                break

        if not found:
            print("Request not found")

    elif role == "4":
        selected = input("Enter approved request IDs separated by spaces: ").split()

        encrypted_total = None
        valid = True
        seen = []

        for rid in selected:
            if rid in seen:
                print("Duplicate ID:", rid)
                valid = False
                break

            seen.append(rid)
            found = False

            for r in requests:
                if r["id"] == rid:
                    found = True

                    actual_hash = hashlib.sha256(r["description"]).hexdigest()

                    message = (
                        r["id"] + "|" + r["region"] + "|" +
                        r["hash"] + "|" +
                        str(r["amount"].ciphertext())
                    ).encode()

                    hash_value = int.from_bytes(hashlib.sha256(message).digest(), "big") % n

                    signature_valid = (pow(r["signature"], e, n) == hash_value)

                    if r["status"] != "APPROVED":
                        print(rid, "is not approved")
                        valid = False

                    elif not r["audited"]:
                        print(rid, "has not been audited")
                        valid = False

                    elif (actual_hash != r["hash"]
                          or not signature_valid):
                        print(rid, "failed verification")
                        valid = False

                    else:
                        if encrypted_total is None:
                            encrypted_total = r["amount"]
                        else:
                            encrypted_total += r["amount"]

                    break

            if not found:
                print("Request not found:", rid)
                valid = False

        if valid and encrypted_total is not None:
            total = private_key.decrypt(encrypted_total)
            print("Final relief fund total:", total)
        else:
            print("Aggregation denied")

    elif role == "5":
        rid = input("Request ID: ")
        found = False

        for r in requests:
            if r["id"] == rid:
                found = True

                if r["status"] != "PENDING":
                    print("Request already processed")
                    break

                decision = input("Approve or reject? ").lower()

                if decision == "approve":
                    r["status"] = "APPROVED"
                    print("Request approved")
                elif decision == "reject":
                    r["status"] = "REJECTED"
                    print("Request rejected")
                else:
                    print("Invalid decision")

                break

        if not found:
            print("Request not found")

    elif role == "6":
        break

    else:
        print("Invalid role")
