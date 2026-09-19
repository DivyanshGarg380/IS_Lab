# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    A military system sends an alphabetic command securely.

    - Roles
        - Commander: enters command → Playfair encryption → AES-CTR encryption.
        - Operator: AES decrypts → Playfair decrypts → displays command.
        - Auditor: can view encrypted command and verify SHA-256, but cannot decrypt.
'''

from Crypto.Cipher import AES
import hashlib

p = 23
g = 5
a = 6
b = 15
A = pow(g, a, p)
B = pow(g, b, p)
alice_secret = pow(B, a, p)
bob_secret = pow(A, b, p)

aes_key = hashlib.sha256(str(alice_secret).encode()).digest()[:16]

nonce = b"12345678"

key = "SECURITY"

def create_matrix(key):
    key = key.upper().replace("J", "I")
    result = ""
    for ch in key + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in result:
            result += ch

    matrix = []
    for i in range(0, 25, 5):
        matrix.append(list(result[i:i+5]))

    return matrix

matrix = create_matrix(key)

def position(ch):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == ch:
                return i, j
            
def prepare(text):
    text = text.upper().replace("J", "I")

    result = ""
    i = 0

    while i < len(text):
        a = text[i]
        if i + 1 < len(text):
            b = text[i + 1]
        else:
            b = "X"

        if a == b:
            result += a + "X"
            i += 1
        else:
            result += a + b
            i += 2

    if len(result) % 2 != 0:
        result += "X"

    return result

def playfair_encrypt(text):
    text = prepare(text)

    result = ""
    for i in range(0, len(text), 2):
        a = text[i]
        b = text[i + 1]

        r1, c1 = position(a)
        r2, c2 = position(b)

        if r1 == r2:
            result += matrix[r1][(c1 + 1) % 5]
            result += matrix[r2][(c2 + 1) % 5]

        elif c1 == c2:
            result += matrix[(r1 + 1) % 5][c1]
            result += matrix[(r2 + 1) % 5][c2]

        else:
            result += matrix[r1][c2]
            result += matrix[r2][c1]

    return result


def playfair_decrypt(text):
    result = ""

    for i in range(0, len(text), 2):
        a = text[i]
        b = text[i + 1]

        r1, c1 = position(a)
        r2, c2 = position(b)

        if r1 == r2:
            result += matrix[r1][(c1 - 1) % 5]
            result += matrix[r2][(c2 - 1) % 5]

        elif c1 == c2:
            result += matrix[(r1 - 1) % 5][c1]
            result += matrix[(r2 - 1) % 5][c2]

        else:
            result += matrix[r1][c2]
            result += matrix[r2][c1]

    return result

# Commander
def commander():
    global encrypted_command
    global stored_hash

    command = input("Enter command (uppercase letters only): ")

    playfair_text = playfair_encrypt(command)
    data = playfair_text.encode()

    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)

    encrypted_command = cipher.encrypt(data)
    stored_hash = hashlib.sha256(encrypted_command).hexdigest()

    print("Playfair Ciphertext:", playfair_text)
    print("AES Ciphertext:", encrypted_command.hex())
    print("SHA-256:", stored_hash)
    
# Operator
def operator():
    if encrypted_command is None:
        print("No encrypted command")
        return

    current_hash = hashlib.sha256(encrypted_command).hexdigest()

    if current_hash != stored_hash:
        print("Hash Verification Failed")
        print("Command Tampered")
        return

    print("Hash Verification Successful")

    cipher = AES.new(aes_key, AES.MODE_CTR, nonce=nonce)

    playfair_text = cipher.decrypt(encrypted_command).decode()
    command = playfair_decrypt(playfair_text)

    print("Playfair Ciphertext:", playfair_text)
    print("Original Command:", command)

# Auditor
def auditor():
    if encrypted_command is None:
        print("No encrypted command")
        return

    current_hash = hashlib.sha256(encrypted_command).hexdigest()

    print("AES Ciphertext:", encrypted_command.hex())
    print("Stored Hash:", stored_hash)
    print("Current Hash:", current_hash)

    if current_hash == stored_hash:
        print("Integrity Verified")
    else:
        print("Integrity Failed")

    print("Auditor cannot decrypt the command")

while True:
    print("1. Commander")
    print("2. Operator")
    print("3. Auditor")
    print("0. Exit")

    choice = int(input("Enter choice: "))

    if choice == 1:
        commander()

    elif choice == 2:
        operator()

    elif choice == 3:
        auditor()

    elif choice == 0:
        break

    else:
        print("Invalid choice")