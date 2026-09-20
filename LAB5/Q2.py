# Socket Programming + Hash-Based Integrity Verification

# SERVER SIDE

import socket

def custom_hash(message):
    hash_val = 5381
    for ch in message:
        hash_val = (hash_val * 33) + ord(ch)
        hash_val = hash_val ^ (hash_val >> 16)
        hash_val = hash_val & 0xFFFFFFFF
        
    return hash_val

server = socket.socket()
server.bind(("localhost", 9999))
server.listen(1)

print("Server is waiting for connection...")

connection, address = server.accept()
print("Connected to:", address)

data = connection.recv(1024).decode()
print("Recieved message:", data) 

server_hash = custom_hash(data)
print("Server hash: ", server_hash)

connection.send(str(server_hash).encode())
connection.close()
server.close()

print("Server closed")

# CLIENT SIDE

import socket 

def custom_hash(message):
    hash_val = 5381
    for ch in message:
        hash_val = (hash_val * 33) + ord(ch)
        hash_val = hash_val ^ (hash_val >> 16)
        hash_val = hash_val & 0xFFFFFFFF
        
    return hash_val

client = socket.socket()
client.connect(("localhost", 9999))

message = input("Enter message to send")

client_hash = custom_hash(message)

print("Client hash: ", client_hash)

client.send(message.encode())

server_hash = int(client.recv(1024).decode())
print("Hash received from server: ", server_hash)

if client_hash == server_hash:
    print("Data verified")
else:
    print("Data check failed")
    
    
client.close()
