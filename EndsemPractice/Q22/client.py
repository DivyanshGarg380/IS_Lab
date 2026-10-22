# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    An industrial sensor sends readings to a server. 
    The client and server derive a shared AES key using Diffie–Hellman. 
    The client encrypts its message using AES-CBC and sends its SHA-256 hash. 
    The server decrypts the message and verifies its integrity before accepting it.

    Requirements:
    - Use TCP sockets.
    - Use Diffie–Hellman with p=23, g=5, a=6, b=15.
    - Derive a 256-bit AES key from the shared secret.
    - Only Client can submit readings.
    - Only Admin can view the server's audit log.
    - Provide a menu-driven client.
    - No JSON or file operations.
'''

import socket
import hashlib 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad 

p, g = 23, 5
a, b = 6, 15

A = pow(g, a, p)
B = pow(g, b, p)

key1 = pow(B, a, p)
key2 = pow(A, b, p)

aes_key = hashlib.sha256(str(key2).encode()).digest()
iv = b"1234567890123456"

while True:
    print("\n1. Submit Sensor Reading")
    print("2. View Audit Log")
    print("0. Exit")

    choice = input("Choice: ")
    
    if choice == "0":
        break
    
    role = input("Role (Client/Admin): ")
    
    if choice == "1":
        reading = input("Enter sensor reading: ")
        data = reading.encode()
        
        digest = hashlib.sha256(data).hexdigest()
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data, 16))
        
        request = role + "|1|" + iv.hex() + "|" + ciphertext.hex() + "|" + digest
        
    elif choice == "2":
        request = role + "|2"
        
    else:
        print("Invalid choice")
        continue
    
    client = socket.socket()
    client.connect(("127.0.0.1", 5000))
    client.sendall(request.encode())
    
    response = client.recv(8192).decode()
    client.close()
    
    print("Server response:")
    print(response)
                         
