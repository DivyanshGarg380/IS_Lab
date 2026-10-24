# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    Develop a menu-driven program with two roles:
        - Researcher: Submit a document with a document ID and description. Encrypt the description using AES-192-CBC, calculate its SHA-256 hash, and generate an HMAC-SHA256 search token for each keyword in the description.
        - Reviewer: Search for a keyword such as climate using its HMAC token. Return matching document IDs without decrypting the descriptions. The reviewer can also view the encrypted description as a hexadecimal dump.
        - Administrator: Verify the integrity of a selected document.
    
    - Constraints: no files, no JSON, fixed keys, and reject duplicate document IDs.
'''

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac

key = b"123456789012345678901234"
iv = b"1234567890123456"
search_key = b"search-secret-key"

p, q, e = 61, 53, 17
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

documents = []

while True:
    print("\n1. Researcher")
    print("2. Reviewer")
    print("3. Administrator")
    print("4. Exit")

    role = input("Choose role: ")

    if role == "1":
        doc_id = input("Document ID: ")

        found = False
        for doc in documents:
            if doc["id"] == doc_id:
                found = True
                break
        
        if found:
            print("Document ID already exists")
            continue

        description = input("Description: ")
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(description.encode(), AES.block_size))
        
        digest = hashlib.sha256(encrypted).hexdigest()
        tokens = []
        for word in description.lower().split():
            token = hmac.new(search_key, word.encode(), hashlib.sha256).hexdigest()
            
            if token not in tokens:
                tokens.append(token)
                
        documents.append({
            "id": doc_id,
            "encrypted": encrypted,
            "hash": digest,
            "tokens": tokens
        })
        
        print("Document stored securely")
        
    elif role == "2":
        print("\n1. Search keyword")
        print("2. View encrypted description")
        action = input("Choose: ")

        if action == "1":
            keyword = input("Enter keyword to search: ").lower()
            
            search_token = hmac.new(search_key, keyword.encode(), hashlib.sha256).hexdigest()
            
            found = False
            for doc in documents:
                if search_token in doc["tokens"]:
                    print("Matching Document ID:", doc["id"])
                    found = True
                    
            if not found:
                print("No matching documents")
                
        elif action == "2":
            doc_id = input("Document ID: ")
            found = False

            for doc in documents:
                if doc["id"] == doc_id:
                    print("Encrypted description:", doc["encrypted"].hex())
                    found = True
                    break
                
            if not found:
                print("Document not found")

    elif role == "3":
        doc_id = input("Document ID to verify: ")
        found = False
        
        for doc in documents:
            if doc["id"] == doc_id:
                found = True 
                actual_hash = hashlib.sha256(doc["encrypted"]).hexdigest()
                if actual_hash == doc["hash"]:
                    print("Integrity Verified")
                else:
                    print("Integrity Failed")
                    
                    
                break
            
        if not found:
            print("Document not found")
            
    elif role == "4":
        break 
    
    else:
        print("Invalid role")
        
    