# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

import socket
import hashlib
import hmac
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from phe import paillier

aes_key = b"12345678901234567890123456789012"
p, g, x = 467, 2, 127
y = pow(g, x, p)
public_key, private_key = paillier.generate_paillier_keypair()

search_key = b"election-search-key"
ballots = []
audit = []

deadline = "2026-12-31 23:59:59"

server = socket.socket()
server.bind(("127.0.0.1", 5000))
server.listen(5)

print("Election server running...")

while True:
    conn, addr = server.accept()
    request = conn.recv(16384).decode()
    fields = request.split("|")
    
    role = fields[0]
    choice = fields[1]
    
    if choice == "1":
        if role != "Voter":
            conn.sendall(b"ACCESS DENIED")
            continue
            
        iv = bytes.fromhex(fields[2])
        ciphertext = bytes.fromhex(fields[3])
        received_hash = fields[4]
        r, s = int(fields[5]), int(fields[6])
        encrypted_votes = [int(v) for v in fields[7:10]]
        
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        data = unpad(cipher.decrypt(ciphertext), 16)
        
        digest = hashlib.sha256(data).digest()
        hash_ok = hmac.compare_digest(digest.hex(), received_hash)
        
        H = int.from_bytes(digest, "big") % (p - 1)
        signature_ok = pow(g, H, p) == (pow(y, r, p) * (pow(r, s, p)) % p)
        
        voter, constituency, candidate, timestamp = data.decode().split("|")
        
        time_ok = timestamp <= deadline
        
        if not (hash_ok and signature_ok and time_ok):
            conn.sendall(b"BALLOT REJECTED")
            continue 
        
        vote_numbers = [
            paillier.EncryptedNumber(public_key, c) for c in encrypted_votes
        ]
        
        ballots.append({
            "constituency": constituency,
            "timestamp": timestamp,
            "votes": vote_numbers
        })
        
        audit.append("Accepted ballot from " + voter)
        conn.sendall(b"BALLOT ACCEPTED")
        
    elif choice == "2":
        if role != "Admin":
            conn.sendall(b"ACCESS DENIED")
            continue
        
        constituency = fields[2]
        token = hmac.new(search_key, constituency.encode(), hashlib.sha256).hexdigest()
        
        found = []
        for i, ballot in enumerate(ballots):
            saved = hmac.new(search_key, ballot["constituency"].encode(), hashlib.sha256).hexdigest()
            
            if hmac.compare_digest(token, saved):
                found.append(str(i+1))
                
        conn.sendall(("Matching Ballots: " + ",".join(found)).encode())
        
    elif choice == "3":
        if role != "Admin":
            conn.sendall(b"ACCESS DENIED")
            continue
        
        totals = [ballots[0]["votes"][i] for i in range(3)]
        
        for ballot in ballots[1:]:
            for i in range(3):
                totals[i] += ballot["votes"][i]
                
        result = []
        for i, total in enumerate(totals):
            result.append("Candidate " + str(i + 1) + ": " + str(private_key.decrypt(total)))
            
        conn.sendall("\n".join(result).encode())
        
    elif choice == "4":
        if role != "Admin":
            conn.sendall(b"ACCESS DENIED")
        else:
            conn.sendall("\n".join(audit).encode())
            
    else:
        conn.sendall(b"INVALID CHOICE")
        
    conn.close()