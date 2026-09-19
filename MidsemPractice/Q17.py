# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    SecureVault: Level Up

    - A company wants a secure file-transfer system using Diffie-Hellman + AES-256-CTR + SHA-256 + ElGamal Digital Signature + RBAC.
    - Roles: 
        - Sender
            - Enter a file/message
            - Generate DH shared secret
            - Encrypt using AES-256-CTR
            - Compute SHA-256 of ciphertext
            - Sign the hash using ElGamal
            - Store ciphertext + hash + signature in files
        
        - Receiver
            - Verify SHA-256
            - Verify ElGamal signature
            - If valid and access is active, decrypt and display plaintext
            - Cannot revoke access
        
        - Security Officer
            - View ciphertext metadata
            - Verify hash + signature
            - Can revoke Receiver access
            - Cannot decrypt plaintext
        
        - Admin
            - View all metadata
            - Can restore/re-enable Receiver access
            - Cannot decrypt plaintext
'''

from Crypto.Cipher import AES
import hashlib
from datetime import datetime
import os

dh_p = 23
dh_g = 5

sender_private = 6
receiver_private = 15

sender_public = pow(dh_g, sender_private, dh_p)
receiver_public = pow(dh_g, receiver_private, dh_p)

shared_secret_sender = pow(receiver_public, sender_private, dh_p)
shared_secret_receiver = pow(sender_public, receiver_private, dh_p)

shared_secret = shared_secret_sender

aes_key = hashlib.sha256(str(shared_secret).encode()).digest()

nonce = b"12345678"

eg_p = 467
eg_g = 2
eg_x = 127
eg_y = pow(eg_g, eg_x, eg_p)
eg_k = 53


def sign_hash(hash_value):
    h = int(hash_value, 16) % (eg_p - 1)
    r = pow(eg_g, eg_k, eg_p)
    k_inverse = pow(eg_k, -1, eg_p - 1)
    s = (k_inverse * (h - eg_x * r)) % (eg_p - 1)
    return r, s


def verify_signature(hash_value, r, s):
    h = int(hash_value, 16) % (eg_p - 1)
    left = pow(eg_g, h, eg_p)
    right = (pow(eg_y, r, eg_p) * pow(r, s, eg_p)) % eg_p
    return left == right

receiver_access = True

# Sender
def sender():
    message = input("Enter file/message content: ")

    plaintext = message.encode()

    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)

    ciphertext = cipher.encrypt(plaintext)

    with open("secure_data.enc", "wb") as file:
        file.write(ciphertext)

    hash_value = hashlib.sha256(ciphertext).hexdigest()

    r, s = sign_hash(hash_value)

    with open("metadata.txt", "w") as file:
        file.write("SHA256=" + hash_value + "\n")
        file.write("Signature_r=" + str(r) + "\n")
        file.write("Signature_s=" + str(s) + "\n")
        file.write("Timestamp=" + str(datetime.now()) + "\n")
        file.write("ReceiverAccess=" + str(receiver_access) + "\n")

    print("File encrypted successfully")
    print("DH Shared Secret:", shared_secret)
    print("AES-256 Key:", aes_key.hex())
    print("SHA-256:", hash_value)
    print("ElGamal Signature:", r, s)

def read_metadata():
    data = {}
    with open("metadata.txt", "r") as file:
        for line in file:
            key, value = line.strip().split("=", 1)
            data[key] = value

    return data

# Receiver
def receiver():
    if not os.path.exists("secure_data.enc"):
        print("No encrypted file found")
        return

    if not os.path.exists("metadata.txt"):
        print("No metadata found")
        return

    if not receiver_access:
        print("ACCESS DENIED: Receiver access has been revoked")
        return

    metadata = read_metadata()

    stored_hash = metadata["SHA256"]

    r = int(metadata["Signature_r"])
    s = int(metadata["Signature_s"])

    with open("secure_data.enc", "rb") as file:
        ciphertext = file.read()

    current_hash = hashlib.sha256(ciphertext).hexdigest()

    print("Checking SHA-256...")

    if current_hash != stored_hash:
        print("HASH VERIFICATION FAILED")
        print("File may have been tampered with")
        return

    print("SHA-256 verified")

    print("Checking ElGamal signature...")

    if not verify_signature(current_hash, r, s):
        print("SIGNATURE VERIFICATION FAILED")
        return

    print("ElGamal Signature verified")

    cipher = AES.new(aes_key, AES.MODE_CTR,nonce=nonce)

    plaintext = cipher.decrypt(ciphertext)

    print("Decryption successful")
    print("Original Message:", plaintext.decode())


# Security Officer
def security_officer():
    global receiver_access

    if not os.path.exists("metadata.txt"):
        print("No metadata found")
        return

    metadata = read_metadata()

    print("SHA-256:", metadata["SHA256"])
    print("Signature r:", metadata["Signature_r"])
    print("Signature s:", metadata["Signature_s"])
    print("Timestamp:", metadata["Timestamp"])
    print("Receiver Access:", receiver_access)

    r = int(metadata["Signature_r"])
    s = int(metadata["Signature_s"])

    if verify_signature(metadata["SHA256"],r,s):
        print("Signature: VALID")
    else:
        print("Signature: INVALID")

    print("\n1. Revoke Receiver Access")
    print("2. Return")

    choice = int(input("Enter choice: "))

    if choice == 1:
        receiver_access = False
        with open("metadata.txt", "a") as file:
            file.write("\nReceiverAccess=False")

        print("Receiver access revoked")

# Admin
def admin():
    global receiver_access

    if os.path.exists("metadata.txt"):
        metadata = read_metadata()

        print("SHA-256:", metadata["SHA256"])
        print("Signature r:", metadata["Signature_r"])
        print("Signature s:", metadata["Signature_s"])
        print("Timestamp:", metadata["Timestamp"])

    print("\n1. Restore Receiver Access")
    print("2. Return")

    choice = int(input("Enter choice: "))

    if choice == 1:
        receiver_access = True
        with open("metadata.txt", "a") as file:
            file.write("\nReceiverAccess=True")

        print("Receiver access restored")

# Tamper
def tamper_ciphertext():
    if not os.path.exists("secure_data.enc"):
        print("No encrypted file found")
        return

    with open("secure_data.enc", "rb") as file:
        data = bytearray(file.read())

    if len(data) == 0:
        print("File is empty")
        return

    data[0] = data[0] ^ 1
    with open("secure_data.enc", "wb") as file:
        file.write(data)

    print("Ciphertext tampered successfully")

while True:
    print("1. Sender")
    print("2. Receiver")
    print("3. Security Officer")
    print("4. Admin")
    print("5. Tamper Ciphertext")
    print("0. Exit")

    choice = int(input("Enter choice: "))

    if choice == 1:
        sender()

    elif choice == 2:
        receiver()

    elif choice == 3:
        security_officer()

    elif choice == 4:
        admin()

    elif choice == 5:
        tamper_ciphertext()

    elif choice == 0:
        break

    else:
        print("Invalid choice")