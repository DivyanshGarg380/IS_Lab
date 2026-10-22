# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    A company wants a client-server system where a client submits a message to the server. 
    The server computes its SHA-256 hash and creates an RSA digital signature. 
    The client verifies both the hash and signature using the server's public key.

    Requirements:
    - Use TCP socket programming.
    - Only clients with the Client role can submit messages.
    - The server returns the hash and signature.
    - The client verifies the signature using RSA.
    - Use fixed RSA parameters: p=61, q=53, e=17.
    - No JSON or file operations.
'''

import socket
import hashlib 

p,q,e = 61, 53, 17
n = p*q

role = input("Enter role (Client): ")
message = input("Enter message: ")

client = socket.socket()
client.connect(("127.0.0.1", 5000))

client.sendall((role + "|" + message).encode())
response = client.recv(4096).decode()
client.close()

if response == "ACCESS DENIED" or response == "INVALID REQUEST":
    print(response)
else:
    digest_hex, signature = response.split("|")
    signature = int(signature)
    
    digest = hashlib.sha256(message.encode()).digest()
    local_hash = digest.hex()
    
    h = int.from_bytes(digest, "big") % n 
    verified_hash = pow(signature, e, n)
    
    print("Server hash:", digest_hex)
    print("Local hash:", local_hash)
    print("Hash matches:", digest_hex == local_hash)
    print("Signature valid:", verified_hash == h)