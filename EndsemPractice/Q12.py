# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
A company maintains confidential documents. Implement a simplified Public-Key Searchable Encryption (PKSE) system using manually implemented RSA. 
Encrypt document contents using AES, build an encrypted keyword index using RSA-encrypted keyword tokens, and allow users to search for a keyword using the public key. 
Return matching document IDs and decrypt only the matching documents.
'''

import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

p,q,e = 61, 53, 17
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

def rsa_encrypt(m):
    return pow(m, e, n)

def rsa_decrypt(c):
    return pow(c, d, n)

def keyword_token(word):
    digest = hashlib.sha256(word.lower().encode()).digest()
    return int.from_bytes(digest, "big") % n 

documents = {
    "D1": "network security encryption",
    "D2": "database encryption",
    "D3": "network monitoring"
}

aes_key = get_random_bytes(16)
encrypted_docs = {}
encrypted_index = {}

for doc_id, text in documents.items():
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(text.encode(), 16))
    
    encrypted_docs[doc_id] = (iv, ciphertext)
    
    for word in set(text.lower().split()):
        token = rsa_encrypt(keyword_token(token))
        encrypted_index.setdefault(token, []).append(doc_id)
        
query = input("Enter search keyword: ").strip().lower()
query_token = rsa_encrypt(keyword_token(query))
matches = encrypted_index.get(query_token, [])

if not matches:
    print("No matches found")
else:
    print("Matches found: ", matches)
    for doc_id in matches:
        iv, ciphertext = encrypted_docs[doc_id]
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), 16).decode()
        print(doc_id, ":", plaintext)


