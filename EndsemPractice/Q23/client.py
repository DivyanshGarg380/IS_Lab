# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    National E-Voting System using Socket Programming
    
    - Client: prepares and submits a vote.
    - Server: verifies the hash and ElGamal signature, checks the timestamp, and stores the encrypted ballot.
    - Admin: searches by constituency and tallies encrypted votes.
    - Tally authority: decrypts the final aggregate.
    - Communication: TCP sockets, with simple |-separated messages.
    
    REVISITED THIS PYQ as of Q14.py
'''

import socket
import hashlib 
from datetime import datetime 
from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad
from phe import paillier

aes_key = b"12345678901234567890123456789012"
iv = b"1234567890123456"

p, g, x, k = 467, 2, 127, 53
n = p * g
y = pow(g, x, p)

public_key, private_key = paillier.generate_paillier_keypair()

while True:
    print("\n1. Cast Vote")
    print("2. Search Constituency (Admin)")
    print("3. Tally Votes (Admin)")
    print("4. View Audit (Admin)")
    print("0. Exit")

    choice = input("Choice: ")
    if choice == "0":
        break
    
    role = input("Role (Voter/Admin): ")
    
    if choice == "1":
        voter = input("Voter ID: ")
        constituency = input("Constituency ID: ")
        candidate = int(input("Candidate ID (1-3): "))
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        message = voter + "|" + constituency + "|" + str(candidate) + "|" + timestamp
        data = message.encode()
        
        digest = hashlib.sha256(data).digest()
        digest_hex = digest.hex()
        
        H = int.from_bytes(digest, "big") % (p - 1)
        r = pow(g, k, p)
        s = (pow(k, -1, p - 1) * (H - x * r)) % (p - 1)
        
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data, 16))
        
        encrypted_votes = []
        for c in [1, 2, 3]:
            value = 1 if candidate == c else 0
        encrypted_votes.append(public_key.encrypt(value).ciphertext())
        
        request = role + "|1|" + iv.hex() + "|" + ciphertext.hex() + "|" + digest_hex + "|" + str(r) + "|" + str(s) + "|".join(str(v) for v in encrypted_votes)
        
    elif choice == "2":
        constituency = input("Constituency ID: ")
        request = role + "|2|" + constituency
        
    elif choice == "3":
        request = role + "|3"
        
    elif choice == "4":
        request = role + "|4"
        
    else:
        print("Invalid choice")
        continue
    
    client = socket.socket()
    client.connect(("127.0.0.1", 5000))
    client.sendall(request.encode())
    response = client.recv(16384).decode()
    client.close()
    
    print("Server response:\n", response)