# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    - An industrial plant collects sensor readings from multiple machines. 
    - Implement a menu-driven program that establishes a shared secret using Diffie–Hellman, encrypts sensor messages using AES-CBC, verifies integrity using SHA-256, encrypts numerical readings using RSA, and calculates the aggregate of encrypted readings using Paillier. 
    - Only the Engineer may submit readings, and only the Admin may view the final aggregate.
'''

import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from phe import paillier

p, g = 23, 5
a, b = 6, 15

A = pow(g, a, p)
B = pow(g, b, p)
secret1 = pow(B, a, p)
secret2 = pow(A, b, p)

aes_key = hashlib.sha256(str(secret1).encode()).hexdigest()
iv = b"1234567890123456"

rp, rq, e = 11, 13, 7
n = rp * rq 
phi = (rp - 1) * (rq - 1)
d = pow(e, -1, phi)

pub, priv = paillier.generate_paillier_keypair()

readings = []

while True:
    print("\n1. Submit Sensor Reading")
    print("2. Verify and Decrypt Message")
    print("3. Show Encrypted Aggregate")
    print("4. Decrypt Final Aggregate")
    print("0. Exit")
    
    choice = input("Choice: ")
    role = input("Role (Engineer/Admin): ")
    
    if choice == "1":
        if role != "Engineer":
            continue
        
        machine = input("Machine ID: ")
        reading = int(input("Sensor reading: "))
        message = machine + ":" + str(reading)
        
        data = message.encode()
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(data, 16))
        
        digest = hashlib.sha256(data).hexdigest()
        
        encrypted_reading = pow(reading % n, e, n)
        
        encrypted_val = pub.encrypted(reading)
        
        readings.append({
            "machine": machine,
            "ciphertext": encrypted,
            "hash": digest,
            "rsa": encrypted_reading,
            "value": encrypted_val
        })
        
        print("Encrypted message (hex):", encrypted.hex())
        print("SHA-256:", digest)
        print("RSA ciphertext:", encrypted_reading)
        print("Paillier ciphertext:", encrypted_val.ciphertext())
        
    elif choice == "2":
        idx = int(input("Reading number: ")) - 1
        record = readings[idx]
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(record["ciphertext"]), 16)
        
        digest = hashlib.sha256(plaintext).hexdigest()
        
        print("Recovered text:", plaintext.decode())
        print("Hash matches:", digest == record["hash"])
        
    elif choice == "3":
        if role != "Admin":
            print("Access denied")
            continue

        total = readings[0]["value"]
        for record in readings[1:]:
            total += record["value"]
            
        print("Encrypted aggregate:", total.ciphertext())
        
    elif choice == "4":
        if role != "Admin":
            print("Access denied")
            continue
        
        total = readings[0]["value"]
        for record in readings[1:]:
            total += record["value"]

        print("Final aggregate:", priv.decrypt(total))
        
    elif choice == "0":
        break

    else:
        print("Invalid choice")