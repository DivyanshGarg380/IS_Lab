# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    - A bank stores encrypted transactions. 
    - Implement a menu-driven Python program to encrypt transaction details using AES-CBC, hash them using SHA-256, sign the hash using RSA, encrypt transaction amounts using Paillier, and calculate the total amount without decrypting individual encrypted amounts. 
    - Only a Customer can submit transactions, while an Auditor can verify transactions and the Admin can decrypt the final aggregate.
'''

import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from phe import paillier

aes_key = b"12345678901234567890123456789012"
iv = b"1234567890123456"

p, q, e = 61, 53, 17
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

pub, priv = paillier.generate_paillier_keypair()

transactions = []

while True:
    print("\n1. Submit Transaction")
    print("2. Verify Transaction")
    print("3. Show Encrypted Total")
    print("4. Decrypt Final Total")
    print("0. Exit")

    choice = input("Choice: ")
    role = input("Role (Customer/Auditor/Admin): ")

    if choice == "1":
        if role != "Customer":
            print("Access denied")
            continue

        account = input("Account ID: ")
        amount = int(input("Transaction amount: "))

        if amount < 0:
            print("Invalid amount")
            continue

        message = account + ":" + str(amount)
        data = message.encode()

        digest = hashlib.sha256(data).digest()
        digest_hex = digest.hex()
        
        hash_number = int.from_bytes(digest, "big") % n
        signature = pow(hash_number, d, n)
        
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(data, 16))

        encrypted_amount = pub.encrypt(amount)
        transactions.append({
            "ciphertext": encrypted,
            "hash": digest_hex,
            "signature": signature,
            "amount": encrypted_amount
        })
        
        print("Encrypted transaction:", encrypted.hex())
        print("SHA-256:", digest_hex)
        print("RSA signature:", signature)
        print("Transaction stored.")
        
    elif choice == "2":
        if role != "Auditor":
            print("Access denied")
            continue

        idx = int(input("Transaction number (starting at 1): ")) - 1
        
        record = transactions[idx]
        
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        data = unpad(cipher.decrypt(record["ciphertext"]), 16)
        digest = hashlib.sha256(data).digest()
        
        hash_number = int.from_bytes(digest, "big") % n
        verified = pow(record["signature"], e, n) == hash_number
        
        print("Recovered transaction:", data.decode())
        print("Hash matches:", digest.hex() == record["hash"])
        print("Signature valid:", verified)
        
    elif choice == "3":
        if role != "Admin":
            print("Access denied")
            continue
        
        total = transactions[0]["amount"]
        for record in transactions[1:]:
            total = total + record["amount"]

        print("Encrypted total:", total.ciphertext())
        
    elif choice == "4":
        if role != "Admin":
            print("Access denied")
            continue
        
        total = transactions[0]["amount"]
        for record in transactions[1:]:
            total = total + record["amount"]

        print("Final total:", priv.decrypt(total))

    elif choice == "0":
        break

    else:
        print("Invalid choice")

