# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
Implement a searchable encrypted document system using AES-128 in CBC mode and HMAC-SHA256. 
Encrypt three documents, create a secure keyword index, and search for a user-provided keyword without decrypting every document. 
Decrypt and display only the matching documents.
'''

import re
import hmac
import hashlib 
from Crypto.Cipher import AES 
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

docs = {
    "D1": "The doctor treats the patient",
    "D2": "The nurse checks the patient",
    "D3": "The doctor writes a report"
}

aes_key = get_random_bytes(16)
index_key = get_random_bytes(32)

def encrypt(text):
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(text.encode(), 16))
    return iv, ciphertext

def decrypt(iv, ciphertext):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintxt = unpad(cipher.decrypt(ciphertext), 16)
    return plaintxt.decode()

def token(word):
    word = word.lower()
    return hmac.new(index_key, word.encode(), hashlib.sha256).hexdigest()

encrypted_docs = {}
index = {}

for doc_id, text in docs.items():
    encrypted_docs[doc_id] = encrypt(text)
    words = set(re.findall(r"\b[a-zA-Z]+\b", text.lower()))
    for word in words:
        key = token(word)
        index.setdefault(key, []).append(doc_id)
        
        
query = input("Enter keyword to search: ").strip().lower()

if not query or not re.fullmatch(r"[a-zA-Z]+", query):
    print("Invalid keyword!")
else:
    search_token = token(query)
    matches = index.get(search_token, [])

    if matches:
        print("Matching Documents:")

        for doc_id in matches:
            iv, ciphertext = encrypted_docs[doc_id]
            plaintext = decrypt(iv, ciphertext)
            print(doc_id, ":", plaintext)
    else:
        print("No matching documents found.")
