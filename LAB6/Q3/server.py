# server.py

import socket
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

HOST = "127.0.0.1"
PORT = 5000

# Generate RSA keys
key = RSA.generate(2048)

private_key = key
public_key = key.publickey()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((HOST, PORT))
    server.listen(1)

    print("Server listening...")

    conn, address = server.accept()

    with conn:

        print("Connected by:", address)

        # Receive message
        message = conn.recv(1024)

        # Receive signature
        signature = conn.recv(1024)

        print("Received message:", message.decode())

        try:

            # Create SHA-256 hash
            h = SHA256.new(message)

            # Verify signature
            pkcs1_15.new(public_key).verify(
                h,
                signature
            )

            print("Digital signature verified.")
            conn.sendall(b"VALID")

        except ValueError:

            print("Digital signature verification failed.")
            conn.sendall(b"INVALID")
