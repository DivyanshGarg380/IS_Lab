# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    SecureFiles — Affine + ElGamal + SHA-256 + RBAC + File Handling
    - Roles: Sender, Receiver, Auditor
    - Sender: enter confidential message → Affine encrypt → save ciphertext to encrypted.txt → SHA-256 → ElGamal-encrypt hash integer → save hash + encrypted hash + timestamp to metadata.txt.
    - Receiver: read files → verify SHA-256 against stored hash → ElGamal-decrypt stored hash → compare → if both valid, Affine-decrypt and display plaintext.
    - Auditor: view ciphertext, hash, encrypted hash and timestamp; verify integrity/authenticity; cannot decrypt plaintext.
    - Add tamper option that modifies one character in encrypted.txt.
'''

import hashlib
from datetime import datetime

a = 5
b = 8
a_inv = pow(a, -1, 26)

p = 467
g = 2
x = 127
y = pow(g, x, p)
k = 53

cipher_file = "encrypted.txt"
metadata_file = "metadata.txt"

def affine_encrypt(text):
    result = ""
    for ch in text.upper():
        if ch.isalpha():
            value = ord(ch) - ord('A')
            encrypted = (a * value + b) % 26
            result += chr(encrypted + ord('A'))

        else:
            result += ch

    return result

def affine_decrypt(text):
    result = ""
    for ch in text:
        if ch.isalpha():
            value = ord(ch) - ord('A')
            decrypted = (a_inv * (value - b)) % 26
            result += chr(decrypted + ord('A'))

        else:
            result += ch

    return result

def elgamal_encrypt(m):
    c1 = pow(g, k, p)
    s = pow(y, k, p)
    c2 = (m * s) % p
    return c1, c2

def elgamal_decrypt(c1, c2):
    s = pow(c1, x, p)
    s_inv = pow(s, -1, p)
    m = (c2 * s_inv) % p
    return m

def calculate_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

# Sender
def create_file():
    message = input("Enter confidential message: ")

    ciphertext = affine_encrypt(message)

    with open(cipher_file, "w") as f:
        f.write(ciphertext)

    hash_value = calculate_hash(ciphertext)

    hash_int = int(hash_value, 16) % p

    c1, c2 = elgamal_encrypt(hash_int)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(metadata_file, "w") as f:
        f.write(hash_value + "\n")
        f.write(str(c1) + "\n")
        f.write(str(c2) + "\n")
        f.write(timestamp + "\n")

    print("File created successfully.")
    print("Affine Ciphertext:", ciphertext)
    print("SHA-256:", hash_value)
    print("ElGamal Cipher:", (c1, c2))
    print("Timestamp:", timestamp)


# Reciever
def receiver_decrypt():
    try:
        with open(cipher_file, "r") as f:
            ciphertext = f.read()

        with open(metadata_file, "r") as f:
            stored_hash = f.readline().strip()
            c1 = int(f.readline().strip())
            c2 = int(f.readline().strip())
            timestamp = f.readline().strip()

    except FileNotFoundError:
        print("Required files not found.")
        return

    current_hash = calculate_hash(ciphertext)

    if current_hash != stored_hash:
        print("SHA-256 Integrity: INVALID")
        print("Decryption denied.")
        return

    print("SHA-256 Integrity: VALID")

    decrypted_hash = elgamal_decrypt(c1, c2)

    stored_hash_int = int(stored_hash, 16) % p

    if decrypted_hash != stored_hash_int:
        print("ElGamal Authentication: INVALID")
        print("Decryption denied.")
        return

    print("ElGamal Authentication: VALID")

    plaintext = affine_decrypt(ciphertext)

    print("Decrypted Message:", plaintext)
    print("Original Timestamp:", timestamp)


def receiver_view():
    try:
        with open(cipher_file, "r") as f:
            ciphertext = f.read()

        with open(metadata_file, "r") as f:
            stored_hash = f.readline().strip()
            c1 = f.readline().strip()
            c2 = f.readline().strip()
            timestamp = f.readline().strip()

        print("Encrypted File Data:", ciphertext)
        print("Stored SHA-256:", stored_hash)
        print("ElGamal c1:", c1)
        print("ElGamal c2:", c2)
        print("Timestamp:", timestamp)

    except FileNotFoundError:
        print("Required files not found.")


# Auditor
def auditor_view():
    try:
        with open(cipher_file, "r") as f:
            ciphertext = f.read()

        with open(metadata_file, "r") as f:
            stored_hash = f.readline().strip()
            c1 = f.readline().strip()
            c2 = f.readline().strip()
            timestamp = f.readline().strip()

        print("Encrypted Data:", ciphertext)
        print("SHA-256 Hash:", stored_hash)
        print("ElGamal c1:", c1)
        print("ElGamal c2:", c2)
        print("Timestamp:", timestamp)

    except FileNotFoundError:
        print("Required files not found.")


def auditor_verify():
    try:
        with open(cipher_file, "r") as f:
            ciphertext = f.read()

        with open(metadata_file, "r") as f:
            stored_hash = f.readline().strip()
            c1 = int(f.readline().strip())
            c2 = int(f.readline().strip())

    except FileNotFoundError:
        print("Required files not found.")
        return

    current_hash = calculate_hash(ciphertext)

    if current_hash == stored_hash:
        print("File Integrity: VALID")
    else:
        print("File Integrity: INVALID")

    decrypted_hash = elgamal_decrypt(c1, c2)

    stored_hash_int = int(stored_hash, 16) % p

    if decrypted_hash == stored_hash_int:
        print("ElGamal Verification: VALID")
    else:
        print("ElGamal Verification: INVALID")


# Tamper
def tamper_file():
    try:
        with open(cipher_file, "r") as f:
            data = f.read()

        if len(data) > 0:
            data = data[:-1] + ("X" if data[-1] != "X" else "Y")

        with open(cipher_file, "w") as f:
            f.write(data)

        print("encrypted.txt modified successfully.")

    except FileNotFoundError:
        print("Encrypted file not found.")


while True:
    print("1. Sender")
    print("2. Receiver")
    print("3. Auditor")
    print("4. Exit")

    role = int(input("Enter Role: "))

    if role == 1:
        while True:
            print("1. Create Encrypted File")
            print("2. Tamper File")
            print("3. Back")

            choice = int(input("Enter choice: "))

            if choice == 1:
                create_file()

            elif choice == 2:
                tamper_file()

            elif choice == 3:
                break

            else:
                print("Invalid choice.")

    elif role == 2:
        while True:
            print("1. View Encrypted File")
            print("2. Verify and Decrypt")
            print("3. Back")

            choice = int(input("Enter choice: "))

            if choice == 1:
                receiver_view()

            elif choice == 2:
                receiver_decrypt()

            elif choice == 3:
                break

            else:
                print("Invalid choice.")

    elif role == 3:
        while True:
            print("1. View Security Metadata")
            print("2. Verify File")
            print("3. Back")

            choice = int(input("Enter choice: "))

            if choice == 1:
                auditor_view()

            elif choice == 2:
                auditor_verify()

            elif choice == 3:
                break

            else:
                print("Invalid choice.")

    elif role == 4:
        print("Exiting SecureFiles...")
        break

    else:
        print("Invalid role.")
