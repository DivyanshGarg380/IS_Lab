# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

import socket
import hashlib 

p, q, e = 61, 53, 17
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

server = socket.socket()
server.bind(("127.0.0.1", 5000))
server.listen(5)

print("Server waiting for clients...")


while True:
    conn, addr = server.accept()
    data = conn.recv(4096).decode()
    
    role, message = data.split("|", 1)
    if role != "Client":
        conn.sendall(b"ACCESS DENIED")
        
    else:
        digest = hashlib.sha256(message.encode()).digest()
        digest_hex = digest.hex()
        
        h = int.from_bytes(digest, "big") % n
        signature = pow(h, d, n)
        
        response = digest_hex + "|" + str(signature)
        conn.sendall(response.encode())
        
        print("Message received:", message)
        print("SHA-256:", digest_hex)
        print("Signature:", signature)

    conn.close()
        