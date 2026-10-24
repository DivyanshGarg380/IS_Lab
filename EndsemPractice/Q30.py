# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    A security agency stores confidential reports. Each report has a report ID, classification, and description.
        - Analyst: Submit reports. Encrypt descriptions using AES-CBC, generate HMAC-SHA256 tokens for individual keywords, and calculate SHA-256 hashes.
        - Investigator: Search reports by a keyword without decrypting descriptions. Return matching report IDs and classifications. Display the encrypted description as a hex dump when requested.
        - Auditor: Verify report integrity and RSA signatures before allowing a report's description to be decrypted.
        - Administrator: Detect tampering with report metadata and revoke a report.
    
    - Constraints: No files, no JSON, fixed keys and toy RSA parameters, no RSA libraries. Reject duplicate IDs. Search must work on descriptions containing multiple words and repeated keywords.
    - Tricky part: The RSA signature must cover the report ID, classification, and description hash. A change to classification must invalidate verification. Revoked reports must not appear in search results.
'''

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac

key = b"123456789012345678901234"
iv = b"1234567890123456"
search_key = b"intel-search-key"

p = 61
q = 53
n = p * q
phi = (p - 1) * (q - 1)
e = 17
d = pow(e, -1, phi)

reports = []

while True:
    print("\n1. Analyst")
    print("2. Investigator")
    print("3. Auditor")
    print("4. Administrator")
    print("5. Exit")

    role = input("Choose role: ")
    
    if role == "1":
        report_id = input("Report ID: ")
        found = False
        for report in reports:
            if report["id"] == report_id:
                found = True
                break

        if found:
            print("Report ID already exists")
            continue
        
        classification = input("Classification: ").upper()
        description = input("Description: ")

        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(description.encode(), AES.block_size))

        digest = hashlib.sha256(encrypted).hexdigest()

        tokens = []
        for word in description.lower().split():
            token = hmac.new(search_key, word.encode(), hashlib.sha256).hexdigest()
            
            if token not in tokens:
                tokens.append(token)
                
        message = (report_id + "|" + classification + "|" + digest).encode()
        hash_val = int.from_bytes(hashlib.sha256(message).digest(), "big") % n
        
        signature = pow(hash_val, d, n)

        reports.append({
            "id": report_id,
            "classification": classification,
            "encrypted": encrypted,
            "hash": digest,
            "tokens": tokens,
            "signature": signature,
            "revoked": False
        })
        
        print("Report stored and signed")
        
    elif role == "2":
        print("\n1. Search keyword")
        print("2. View encrypted description")
        action = input("Choose: ")
        
        if action == "1":
            keyword = input("Keyword: ").lower()
            
            search_token = hmac.new(search_key, keyword.encode(), hashlib.sha256).hexdigest()
            
            found = False
            for report in reports:
                if (not report["revoked"] and search_token in report["tokens"]):
                    print("Report ID:", report["id"])
                    print("Classification:", report["classification"])
                    found = True
                    
            if not found:
                print("No matching reports")
                
        elif action == "2":
            report_id = input("Report ID: ")
            found = False
            
            for report in reports:
                if report["id"] == report_id and not report["revoked"]:
                    print("Encrypted description:", report["encrypted"].hex())
                    found = True
                    break
                
            if not found:
                print("Report not found or revoked")
                
    elif role == "3":
        report_id = input("Report ID to audit: ")
        found = False

        for report in reports:
            if report["id"] == report_id and not report["revoked"]:
                found = True

                actual_hash = hashlib.sha256(report["encrypted"]).hexdigest()
                
                message = (report["id"] + "|" + report["classification"] + "|" + report["hash"]).encode()
                hash_value = int.from_bytes(hashlib.sha256(message).digest(), "big") % n
                
                signature_ok = pow(report["signature"], e, n) == hash_val
                
                if actual_hash == report["hash"] and signature_ok:
                    print("Integrity and RSA signature verified")
                    
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    plaintext = unpad(cipher.decrypt(report["encrypted"]), AES.block_size).decode()
                    print("Decription: ", plaintext)
                
                else:
                    print("Tampering detected. Decryption denied")

            break 
        
        if not found:
            print("Report not found or revoked")

    elif role == "4":
        report_id = input("Report ID to revoke: ")
        found = False

        for report in reports:
            if report["id"] == report_id:
                found = True

                if report["revoked"]:
                    print("Report already revoked")
                else:
                    report["revoked"] = True
                    print("Report revoked")

                break

        if not found:
            print("Report not found")

    elif role == "5":
        break

    else:
        print("Invalid role")
