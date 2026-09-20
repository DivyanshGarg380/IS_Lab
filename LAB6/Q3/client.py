# client.py

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


# Message to send
message = b"Information Security"


# Create hash
h = SHA256.new(message)


# Sign using private key
signature = pkcs1_15.new(private_key).sign(h)


print("Original message:", message.decode())
print("Digital signature generated.")


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:

    client.connect((HOST, PORT))

    # Send message
    client.sendall(message)

    # Send signature
    client.sendall(signature)

    # Receive verification result
    result = client.recv(1024)

    print("Server response:", result.decode())

    if result == b"VALID":
        print("Signature verified successfully.")
    else:
        print("Signature verification failed.")
