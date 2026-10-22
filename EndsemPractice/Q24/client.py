# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    A client sends a software package's name, version, and SHA-256 hash to a server. 
    The server checks the client's RSA digital signature and decides whether to approve or reject the package. 
    The server also maintains an approval list that only an Admin can view.

    Requirements:
    - Use TCP client-server socket programming.
    - Use fixed RSA parameters: p=61, q=53, e=17.
    - Use Diffie–Hellman to derive a shared secret.
    - Use SHA-256 for package integrity.
    - The client signs the package hash using RSA.
    - Only Developer can submit packages; only Admin can view approvals.
    - No JSON, no files, no unnecessary functions.
'''

import socket
import hashlib 

p, q, e = 61, 53, 17
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

dp, g = 23, 5
a, b = 6, 15

A = pow(g, a, dp)
B = pow(g, b, dp)
shared = pow(B, a, dp)

while True:
    print("\n1. Submit Package")
    print("2. View Approval List")
    print("0. Exit")

    choice = input("Choice: ")

    if choice == "0":
        break

    role = input("Role (Developer/Admin): ")

    if choice == "1":
        name = input("Package name: ")
        version = input("Version: ")
        
        message = name + "|" + version
        digest = hashlib.sha256(message.encode()).digest()
        h = int.from_bytes(digest, "big") % n
        
        signature = pow(h, d, n)
        
        request = role + "|1|" + name + "|" + version + "|" + str(signature)
        
    elif choice == "2":
        request = role + "|2"
        
    else:
        print("Invalid choice")
        
    client = socket.socket()
    client.connect(("127.0.0.1", 5000))
    client.sendall(request.encode())
    
    print("Server: ", client.recv(4096).decode())
    client.close()
    

