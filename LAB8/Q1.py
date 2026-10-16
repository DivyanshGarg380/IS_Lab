import hashlib
import hmac
import re

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Encrypt
def encrypt(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data.encode("utf-8"), AES.block_size))
    return cipher.iv + ciphertext

def decrypt(key, data):
    iv = data[:AES.block_size]
    ciphertext = data[AES.block_size:]
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode("utf-8")

def tokenize(text):
    return re.findall(r"\b[a-z0-9]+\b", text.lower())

def search_token(key, word):
    return hmac.new(key, word.encode("utf-8"), hashlib.sha256).digest()

def create_idx(documents, key):
    index = {}
    for doc_id, document in documents.items():
        for word in set(tokenize(document)):
            token = search_token(key, word)

            if token not in index:
                index[token] = []

            index[token].append(doc_id)
            
    encrypted_index = {}

    for token, doc_ids in index.items():
        encrypted_index[token] = [encrypt(key, doc_id) for doc_id in doc_ids]

    return encrypted_index

def search(encrypted_index, query, key):
    words = tokenize(query)

    if not words:
        return []

    token = search_token(key, words[0])

    if token not in encrypted_index:
        return []

    return [decrypt(key, encrypted_id) for encrypted_id in encrypted_index[token]]

documents = {
    "doc1": "Python supports secure encryption algorithms",
    "doc2": "AES provides symmetric data encryption",
    "doc3": "Public key cryptography uses two keys",
    "doc4": "Searchable encryption protects private documents",
    "doc5": "Network security detects malicious traffic",
    "doc6": "Python programming simplifies data analysis",
    "doc7": "AES encryption uses a secret key",
    "doc8": "Cryptography helps protect sensitive information",
    "doc9": "Secure databases store encrypted records",
    "doc10": "Search systems retrieve matching documents",
}


key = get_random_bytes(32)

encrypted_documents = {
    doc_id: encrypt(key, document)
    for doc_id, document in documents.items()
}

encrypted_index = create_idx(documents, key)

print("Total documents:", len(documents))
print("Encrypted index created successfully.")

query = input("Enter a keyword to search: ").strip()

results = search(encrypted_index, query, key)

print("\nSearch results for:", query)

if results:
    for doc_id in results:
        plaintext = decrypt(key, encrypted_documents[doc_id])
        print(doc_id, ":", plaintext)
else:
    print("No matching documents found.")
