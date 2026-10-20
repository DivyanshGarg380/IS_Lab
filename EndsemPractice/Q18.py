# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    A company distributes firmware updates to IoT devices. Each update must be encrypted using an AES key derived through Diffie–Hellman, hashed using SHA-256, and digitally signed using ElGamal. A device must reject updates with invalid signatures, modified contents, or versions older than the latest accepted version. The server must also support searching updates by component name using searchable encryption.

    Write a menu-driven Python program with these options:
        1. Create and store a firmware update.
        2. Verify and accept an update.
        3. Search updates by component name.
        4. Simulate ciphertext tampering.
        5. Exit.
    
    Use fixed cryptographic parameters, simple in-memory storage, and basic role checks.
'''

import hashlib
import hmac
import json
import math
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

p, g = 23, 5
a, b = 6, 15

A = pow(g, a, p)
B = pow(g, b, p)
key1 = pow(B, a, p)
key2 = pow(A, b, p)

if key1 != key2:
    print("Key exchange failed")
    exit()

aes_key = hashlib.sha256(str(key1).encode()).digest()
iv = b"1234567890123456"

ep, eg, x, k = 467, 2, 127, 53
y = pow(eg, x, ep)

search_key = b"firmware-search-key"

updates = []
highest_version = 0

while True:
    print("\n1. Create Update")
    print("2. Verify Update")
    print("3. Search Component")
    print("4. Tamper With Update")
    print("0. Exit")

    choice = input("Choice: ")
    role = input("Role (Developer/Device/Admin): ")
    
    if choice == "1":
        if role != "Developer":
            print("Access Denied!")
            continue 
        
        component = input("Component name: ")
        version = int(input("Version number: "))
        firmware = input("Firmware contents: ")

        message = component + "|" + str(version) + "|" + firmware

        digest = hashlib.sha256(message.encode()).digest()
        H = int.from_bytes(digest, "big") % (ep - 1)
        
        r = pow(eg, k, ep)
        s = (pow(k, -1, ep - 1) * (H - x * r)) % (ep - 1)

        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(message, 16))
        
        token = hmac.new(search_key, component.encode(), hashlib.sha256).hexdigest()

        updates.append({
            "component": component,
            "version": version,
            "ciphertext": ciphertext,
            "hash": digest.hex(),
            "signature": (r, s),
            "token": token,
            "accepted": False
        })
        
        print("Update stored.")
        print("Ciphertext (hex):", ciphertext.hex())
        print("SHA-256:", digest.hex())
        print("ElGamal signature:", (r, s))
        
    elif choice == "2":
        if role != "Device":
            print("Access denied")
            continue
        
        idx = int(input("Update number (starting at 1): ")) - 1
        
        record = updates[idx]
        try:
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            data = unpad(cipher.decrypt(record["ciphertext"]), 16)

            digest = hashlib.sha256(data).digest()
            hash_ok = hmac.compare_digest(digest.hex(), record["hash"])
            
            H = int.from_bytes(digest, "big") % (ep - 1)
            r, s = record["signature"]
            
            signature_ok = (
                0 < r < ep and 0 <= s < ep - 1
                and pow(eg, H, ep)
                == (pow(y, r, ep) * pow(r, s, ep)) % ep
            )
            
            message = data.decode()
            component, version, firmware = message.split("|")
            version = int(version)
            
            version_ok = version > highest_version

            print("Hash valid:", hash_ok)
            print("Signature valid:", signature_ok)
            print("Version acceptable:", version_ok)
            
            if hash_ok and signature_ok and version_ok:
                highest_version = version
                record["accepted"] = True
                print("Update ACCEPTED")
                print("Component:", component)
                print("Installed version:", version)
                print("Firmware:", firmware)
            else:
                print("Update REJECTED")

        except (ValueError, UnicodeDecodeError):
            print("Update REJECTED: corrupted data")
            
    elif choice == "3":
        if role not in ["Admin", "Device"]:
            print("Access denied")
            continue

        component = input("Component to search: ")
        
        query = hmac.new(search_key, component.encode(), hashlib.sha256).hexdigest()
        
        found = False
        for i, record in enumerate(updates):
            if hmac.compare_digest(query, record["token"]):
                print("Matching update:", i + 1)
                print("Version:", record["version"])
                found = True
        
        if not found:
            print("No matching updates")
            
    elif choice == "4":
        if role != "Admin":
            print("Access denied")
            continue

        idx = int(input("Update number to tamper with: ")) - 1

        ciphertext = bytearray(updates[idx]["ciphertext"])
        ciphertext[0] ^= 1
        updates[idx]["ciphertext"] = bytes(ciphertext)

        print("Ciphertext modified.")
        print("Verify this update to test rejection.")

    elif choice == "0":
        break

    else:
        print("Invalid choice")
