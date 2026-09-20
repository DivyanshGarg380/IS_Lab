# Chunking

# SERVER SIDE

import socket

def custom_hash(message):
    hash_value = 5381
    
    for ch in message:
        hash_value = (hash_value * 33) + ord(ch)
        hash_value = hash_value ^ (hash_value >> 16)
        hash_value = hash_value & 0xFFFFFFFF

    return hash_value


server = socket.socket()
server.bind(("localhost", 9999))
server.listen(1)
print("Server is waiting for connection")

connection, address = server.accept()

print("Conneted to:", address)

number_of_parts = int(connection.recv(1024).decode())

connection.send("OK".encode())

parts = []
for i in range(number_of_parts):
    part = connection.recv(1024).decode()
    parts.append(part)
    connection.send("OK".encode())
    
message = ''.join(parts)
print("Reassembled Message: ", message)

server_hash = custom_hash(message)

print("Server Hash:", server_hash)
connection.send(str(server_hash).encode())

connection.close()
server.close()
print("Server closed.")


# CLIENT SIDE

import socket 

client = socket.socket()
client.connect(("localhost", 9999))

part_size = 5
message = input("Enter message")
client_hash = custom_hash(message)
print("Client Hash: ", client_hash)

parts = []
for i in range(0, len(message), part_size):
    parts.append(message[i:i+part_size])
    
    
client.send(str(len(parts)).encode())
client.recv(1024)

for part in parts:
    client.send(part.encode())
    client.recv(1024)
    
    
server_hash = int(client.recv(1024).decode())
print("Server Hash: ", server_hash)

if client_hash == server_hash:
    print("Data verified")
else:
    print("Data check failed")
    

client.close()