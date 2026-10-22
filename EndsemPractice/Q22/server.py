# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

import socket
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

p, g = 23, 5
a, b = 6, 15

A = pow(g, a, p)
B = pow(g, b, p)

key1 = pow(B, a, p)
key2 = pow(A, b, p)

aes_key = hashlib.sha256(str(key1).encode()).digest()

audit = []

server = socket.socket()
server.bind(("127.0.0.1", 5000))
server.listen(5)

print("Secure sensor server running...")

while True:
    conn, addr = server.accept()
    
    request = conn.recv(8192).decode()
    parts = request.split("|", 2)
    
    if len(parts) < 2:
        conn.sendall(b"INVALID REQUEST")
        conn.close()
        continue
    
    role = parts[0]
    choice = parts[1]
    
    if choice == "1":
        if role != "Client":
            conn.sendall(b"ACCESS DENIED")
            
        else:
            fields = request.split("|", 4)
            
            iv = bytes.fromhex(fields[2])
            ciphertext = bytes.fromhex(fields[3])
            recieved_hash = fields[4]
            
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), 16)
            
            calculated_hash = hashlib.sha256(plaintext).hexdigest()
            if hmac.compare_digest(calculated_hash, recieved_hash):
                message = plaintext.decode()
                audit.append(message)
                conn.sendall(b"ACCEPTED")
                print("Verified reading:", message)
            else:
                conn.sendall(b"HASH MISMATCH")
                
    elif choice == "2":
        if role != "Admin":
            conn.sendall(b"ACCESS DENIED")
        else:
            result = "\n".join(audit)
            if not result:
                result = "Audit log is empty"
            conn.sendall(result.encode())
            
    else:
        conn.sendall(b"INVALID CHOICE")

    conn.close()