# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    A cybercrime investigation system stores digital evidence. 
    Each new evidence record must include the previous record's hash, its own SHA-256 hash, and an RSA digital signature. The auditor must detect modified evidence and broken chain links.

    Write a menu-driven program with RBAC:
    - Investigator: add evidence.
    - Auditor: verify evidence and the complete chain.
    - Admin: simulate evidence tampering.
'''

import hashlib 

p,q,e = 61, 53, 17
n = p*q
phi = (p-1)*(q-1)
d = pow(e, -1, phi)

records = []
previous_hash = "0"

while True:
    print("\n1. Add Evidence")
    print("2. Verify Evidence")
    print("3. Verify Entire Chain")
    print("4. Tamper With Evidence")
    print("0. Exit")

    choice = input("Choice: ")
    role = input("Role (Investigator/Auditor/Admin): ")

    if choice == "1":
        if role != "Investigator":
            print("Access denied")
            continue
        
        evidence = input("Evidence description: ")
        evidence_bytes = evidence.encode()
        evidence_hex = evidence_bytes.hex()
        
        message = previous_hash + "|" + evidence
        data = message.encode()
        
        digest = hashlib.sha256(data).digest()
        digest_hex = digest.hex()
        
        hash_number = int.from_bytes(digest, "big") % n
        
        signature = pow(hash_number, d, n)
        records.append({
            "evidence": evidence_hex,
            "previous_hash": previous_hash,
            "hash": digest_hex,
            "signature": signature
        })
        
        previous_hash = digest_hex

        print("Evidence stored.")
        print("Evidence in hex:", evidence_hex)
        print("SHA-256:", digest_hex)
        print("Signature:", signature)
        
    elif choice == "2":
        if role != "Auditor":
            print("Access denied")
            continue
        
        idx = int(input("Evidence number: ")) - 1
        record = records[idx]
        
        evidence_bytes = bytes.fromhex(record["evidence"])
        evidence = evidence_bytes.decode()
        
        message = record["previous_hash"] + "|" + evidence
        digest = hashlib.sha256(message.encode()).digest()
        
        hash_ok = digest.hex() == record["hash"]
        
        hash_number = int.from_bytes(digest, "big") % n
        signature_ok = (pow(record["signature"], e, n) == hash_number)

        print("Recovered evidence:", evidence)
        print("Hash valid:", hash_ok)
        print("Signature valid:", signature_ok)
        print("Evidence authentic:", hash_ok and signature_ok)
        
    elif choice == "3":
        if role != "Auditor":
            print("Access denied")
            continue

        chain_ok = True
        expected_previous = "0"

        for record in records:
            evidence = bytes.fromhex(record["evidence"]).decode()

            if record["previous_hash"] != expected_previous:
                chain_ok = False
                break

            message = record["previous_hash"] + "|" + evidence
            digest = hashlib.sha256(message.encode()).digest()
            hash_number = int.from_bytes(digest, "big") % n

            if digest.hex() != record["hash"]:
                chain_ok = False
                break

            if pow(record["signature"], e, n) != hash_number:
                chain_ok = False
                break

            expected_previous = record["hash"]

        print("Entire chain valid:", chain_ok)

    elif choice == "4":
        if role != "Admin":
            print("Access denied")
            continue

        idx = int(input("Evidence number to tamper with: ")) - 1

        changed = bytes.fromhex(records[idx]["evidence"])
        records[idx]["evidence"] = (changed + b" MODIFIED").hex()

        print("Evidence modified.")
        print("Run verification to detect tampering.")

    elif choice == "0":
        break

    else:
        print("Invalid choice")