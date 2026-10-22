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

dp, g = 23, 5
a, b = 6, 15

A = pow(g, a, dp)
B = pow(g, b, dp)
shared = pow(A, b, dp)


approvals = []

server = socket.socket()
server.bind(("127.0.0.1", 5000))
server.listen(5)

print("Approval server running....")

while True:
    conn, addr = server.accept()
    request = conn.recv(4096).decode()
    
    fields = request.split("|")
    
    role, choice = fields[0], fields[1]
    
    if choice == "1":
        if role != "Developer":
            conn.sendall(b"ACCESS DENIED")
            continue
        
        name = fields[2]
        version = fields[3]
        signature = int(fields[4])
        
        message = name + "|" + version
        digest = hashlib.sha256(message.encode()).digest()
        h = int.from_bytes(digest, "big") % n
        
        valid = pow(signature, e, n) == h
        
        if valid:
            approvals.append(name + " version " + version)
            conn.sendall(b"PACKAGE APPROVED")
        else:
            conn.sendall(b"PACKAGE REJECTED: INVALID SIGNATURE")
            
    elif choice == "2":
        if role != "Admin":
            conn.sendall(b"ACCESS DENIED")
            continue
        
        else:
            conn.sendall(("\n".join(approvals) or "No approvals yet").encode())
            
    else:
        conn.sendall(b"INVALID CHOICE")
        
    conn.close()
