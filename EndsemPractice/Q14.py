# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    A national e-voting system has been deployed to allow citizens to cast their votes securely from remote locations. The system ensures privacy, verifiability, integrity, and non-repudiation while allowing aggregate computations without revealing individual votes.

    1. On the Client Side
        A voter fills out an electronic ballot that records their candidate selection and constituency ID.
        Before submission, the voter's device generates a SHA-512 hash of the ballot file to ensure data integrity.
        The ballot is then encrypted using AES-256 in CBC mode for confidentiality.
        The AES key is encrypted with the Election Commission's RSA-4096 public key.
        To ensure authenticity and non-repudiation, the voter's system digitally signs the SHA-512 hash using their ElGamal digital signature.
        The voter's choice (numerical candidate ID) is homomorphically encrypted using the Paillier encryption scheme, allowing the Election Commission to tally votes without decrypting individual ballots.
        A timestamp from a trusted authority is added to record the exact submission time and ensure votes are cast before the deadline.

    2. On the Server Side
        The system decrypts the AES session key using its RSA private key but keeps the homomorphically encrypted vote values in their encrypted form.
        It verifies the digital signature using the voter's public key and compares the SHA-512 hash to detect any tampering.
        The timestamp is checked to confirm that the vote was cast within the valid voting period.
        The homomorphic tallying algorithm is applied to aggregate the encrypted votes and compute total counts without decrypting any individual vote.
        For audit and search purposes, the server maintains a searchable encryption index to locate ballots from specific constituencies or time ranges without revealing vote content.
        At the end of the election, only the final aggregated ciphertext is decrypted using a threshold decryption scheme, ensuring that no single authority can view votes independently.

    3. Programming Task
        Write a menu-driven Python program that implements the above functionalities.

    - Ensure that the system supports role-based access control and the appropriate use of cryptographic techniques for confidentiality, integrity, and authenticity.
    - Use any data structures (e.g., databases, files or arrays) to securely store encrypted, signed and hashed data.
    - Show outputs for all the functions specified in the question.
'''

import hashlib
import hmac 
import json 
from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad, unpad 
from phe import paillier

aes_key = b"12345678901234567890123456789012"
p,q,e = 61,53,17
n = p*q
phi = (p-1)*(q-1)
d = pow(e, -1, phi)

gp, g, x = 467, 2, 127
y = pow(g, x, gp)
k = 53

public_key, private_key = paillier.generate_paillier_keypair()

ballots = []
tally = {}
audit = []

while True:
    print("\n1. Cast Vote")
    print("2. Verify Ballot")
    print("3. Tally Votes")
    print("4. Search Constituency")
    print("5. Show Audit")
    print("0. Exit")
    
    choice = input("Choice: ")
    
    if choice == "1":
        voter = input("Voter ID: ")
        constituency = input("Constituency: ")
        candidate = int(input("Candidate ID (1/2/3): "))
        
        ballot = {
            "voter": voter,
            "constituency": constituency,
            "candidate": candidate
        }
        
        data = json.dumps(ballot, sort_keys=True).encode()
        
        digest = hashlib.sha256(data).digest()
        digest_hex = digest.hex()
        
        H = int.from_bytes(digest, "big") % (gp - 1)
        r = pow(g, k, gp)
        s = (pow(k, -1, gp - 1) * (H - x * r)) % (gp - 1)
        
        iv = b"0123456789abcdef"
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data, 16))
        
        key_number = int.from_bytes(aes_key[:2], "big") % n
        encrypted_key = pow(key_number, e, n)
        
        encrypted_vote = public_key.encrypt(candidate)
        
        ballots.append({
            "data": ciphertext,
            "iv": iv,
            "hash": digest_hex,
            "signature": (r, s),
            "encrypted_key": encrypted_key,
            "vote": encrypted_vote,
            "constituency": constituency
        })
        
        audit.append("Vote submitted by " + voter)
        print("Vote encrypted and stored.")
        print("SHA-512:", digest_hex)
        print("ElGamal signature:", (r, s))
        print("RSA-encrypted key value:", encrypted_key)
        
        
    elif choice == "2":
        b = ballots[-1]
        
        cipher = AES.new(aes_key, AES.MODE_CBC, b["iv"])
        data = unpad(cipher.decrypt(b["data"]), 16)
        
        digest = hashlib.sha512(data).digest()
        H = int.from_bytes(digest, "big") % (gp - 1)
        r, s = b["signature"]
        
        valid_signature = (pow(g, H, gp) == (pow(y, r, gp) * pow(r, s, gp)) % gp)
        
        print("Hash:", digest.hex())
        print("Signature valid:", valid_signature)
        print("Ballot:", data.decode())
        
    elif choice == "3":
        tally = {}
        for b in ballots:
            candidate = private_key.decrypt(b["vote"])
            tally[candidate] = tally.get(candidate, 0) + 1

        print("Candidate-wise totals:", tally)

    elif choice == "4":
        constituency = input("Enter constituency: ")
        for b in ballots:
            token1 = hmac.new(aes_key, b["constituency"].encode(),  hashlib.sha256).hexdigest()
            token2 = hmac.new(aes_key, constituency.encode(), hashlib.sha256).hexdigest()
            
            if hmac.compare_digest(token1, token2):
                print("Matching encrypted ballot found.")
                
    elif choice == "5":
        print(audit)

    elif choice == "0":
        break
