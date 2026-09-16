# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    Secure Hospital Messaging

    - Doctor: enter a medical message → encrypt using Playfair with key "MONARCHY".
    - Generate a Diffie-Hellman shared secret using given p, g, private keys.
    - Use the shared secret as the basis for the Playfair key.
    - Receiver: decrypt the Playfair message using the same shared secret.
    - Auditor: view ciphertext + DH public values, but cannot decrypt.
    - RBAC compulsory.
    - Display public keys and shared secret.
'''

p = 23
g = 5
a = 6
b = 15

A = pow(g, a, p)
B = pow(g, b, p)

shared_A = pow(B, a, p)
shared_B = pow(A, b, p)

print("Alice Public Key:", A)
print("Bob Public Key:", B)
print("Alice Shared Secret:", shared_A)
print("Bob Shared Secret:", shared_B)

def create_matrix(key):
    key = key.upper().replace("J", "I")
    matrix = []
    used = ""

    for ch in key + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in used and ch.isalpha():
            used += ch

    for i in range(0, 25, 5):
        matrix.append(list(used[i:i + 5]))

    return matrix


def find_position(matrix, ch):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == ch:
                return i, j
            
    return (0, 0)


def prepare_text(text):
    text = text.upper().replace("J", "I")
    text = ''.join(ch for ch in text if ch.isalpha())

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

    return result


def playfair_encrypt(text, key):
    matrix = create_matrix(key)
    text = prepare_text(text)
    result = ""

    for i in range(0, len(text), 2):
        a = text[i]
        b = text[i + 1]

        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)

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


def playfair_decrypt(text, key):
    matrix = create_matrix(key)
    result = ""

    for i in range(0, len(text), 2):
        a = text[i]
        b = text[i + 1]

        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)

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

ciphertext = ""
message = ""
playfair_key = ""
shared_secret = shared_A

# Doctor
def doctor():
    global ciphertext, message, playfair_key

    message = input("Enter medical message: ")

    # Convert DH shared secret into a Playfair key
    playfair_key = "HOSPITAL" + str(shared_secret)

    ciphertext = playfair_encrypt(message, playfair_key)

    print("\nPlayfair Key:", playfair_key)
    print("Encrypted Message:", ciphertext)

# Reciever
def receiver():
    if ciphertext == "":
        print("No message available.")
        return

    print("\nEncrypted Message:", ciphertext)

    # Use same DH shared secret
    decrypted = playfair_decrypt(ciphertext, playfair_key)

    print("Decrypted Message:", decrypted)
    
# Auditor
def auditor():
    print("Ciphertext:", ciphertext)
    print("Doctor Public Key:", A)
    print("Receiver Public Key:", B)

    # Auditor can see public values
    print("Playfair Decryption: DENIED")
    print("Plaintext Access: DENIED")
    print("Shared Secret Access: DENIED")
    
while True:
    print("1. Doctor")
    print("2. Receiver")
    print("3. Auditor")
    print("0. Exit")

    choice = int(input("Enter role: "))

    if choice == 1:
        doctor()

    elif choice == 2:
        receiver()

    elif choice == 3:
        auditor()

    elif choice == 0:
        break

    else:
        print("Invalid choice.")