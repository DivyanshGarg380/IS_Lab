# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
Implement a searchable encryption system for a collection of text documents. 
Encrypt each document using AES-128-CBC, build a keyword index using HMAC-SHA256, and allow a user to search for a keyword without decrypting every document. Decrypt only matching documents and verify their integrity using SHA-256 before displaying them. 
Keep all data in memory.
'''

import re
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

aes_key = get_random_bytes(16)
idx_key = get_random_bytes(32)

documents = {
    "D1": "network security uses encryption",
    "D2": "database indexing improves searching",
    "D3": "encryption protects database records"
}

encrypted_docs = {}
index = {}

for doc_id, text in documents.items():
    cipher = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(text.encode()), AES.block_size)
    
    digest = hashlib.sha256(ciphertext).hexdigest()
    encrypted_docs[doc_id] = (iv, ciphertext, digest)
    
    words = set(re.findall(r"[a-zA-Z]+", text.lower()))
    for word in words:
        token = hmac.new(idx_key, word.encode(), hashlib.sha256).hexdigest()    
        index.setdefault(token, []).append(doc_id)
        
query = input("Enter keyword to search: ").strip().lower()

query_token = hmac.new(idx_key, query.encode(), hashlib.sha256).hexdigest()

matches = index.get(query_token, [])

if not matches:
    print("No matching documents.")
    exit(0)
    
for doc_id in matches:
    iv, ciphertext, stored_hash = encrypted_docs[doc_id]

    received_hash = hashlib.sha256(ciphertext).hexdigest()

    if stored_hash != received_hash:
        print(doc_id, ": Integrity failed. Access denied.")
        continue

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
    print(doc_id, ":", plaintext)
