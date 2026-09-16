# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    Secure Banking Transaction

    - Customer: enter a transaction message → encrypt using Hill Cipher with key matrix
        -- [[3,3],[2,5]].
    
    - Generate ElGamal public/private keys using p = 467, g = 2, x = 127.
    - Encrypt a numeric transaction authorization code using ElGamal.
    - Bank: decrypt the Hill ciphertext and ElGamal authorization code.
    - Auditor: view Hill ciphertext + ElGamal public key/ciphertext only.
    - RBAC compulsory.
'''

K = [[3, 3], [2, 5]]

def hill_encrypt(text):
    text = text.upper().replace(" ", "")

    while len(text) % 2 != 0:
        text += "X"

    result = ""

    for i in range(0, len(text), 2):
        x1 = ord(text[i]) - ord('A')
        x2 = ord(text[i + 1]) - ord('A')

        y1 = (K[0][0] * x1 + K[0][1] * x2) % 26
        y2 = (K[1][0] * x1 + K[1][1] * x2) % 26

        result += chr(y1 + ord('A'))
        result += chr(y2 + ord('A'))

    return result


def hill_decrypt(text):
    det = K[0][0] * K[1][1] - K[0][1] * K[1][0]
    det = det % 26

    det_inverse = pow(det, -1, 26)

    inverse_matrix = [
        [(K[1][1] * det_inverse) % 26, (-K[0][1] * det_inverse) % 26],
        [(-K[1][0] * det_inverse) % 26, (K[0][0] * det_inverse) % 26]
    ]

    result = ""

    for i in range(0, len(text), 2):
        x1 = ord(text[i]) - ord('A')
        x2 = ord(text[i + 1]) - ord('A')

        y1 = (inverse_matrix[0][0] * x1 + inverse_matrix[0][1] * x2) % 26
        y2 = (inverse_matrix[1][0] * x1 + inverse_matrix[1][1] * x2) % 26

        result += chr(y1 + ord('A'))
        result += chr(y2 + ord('A'))

    return result

# Elgamal
p = 467
g = 2
x = 127

y = pow(g, x, p)

def inverse(a, m):
    return pow(a, -1, m)


def elgamal_encrypt(message):
    k = 3
    c1 = pow(g, k, p)
    shared = pow(y, k, p)
    c2 = (message * shared) % p
    if c1 != 0 and c2 != 0:
        return c1, c2
    
    return 0, 0


def elgamal_decrypt(c1, c2):
    shared = pow(c1, x, p)
    shared_inverse = inverse(shared, p)
    message = (c2 * shared_inverse) % p
    return message

hill_ciphertext = ""
authorization_ciphertext = ()
original_message = ""
authorization_code = 0

# Customer
def customer():
    global hill_ciphertext, authorization_ciphertext
    global original_message, authorization_code

    original_message = input("Enter transaction message: ")

    # Hill encryption
    hill_ciphertext = hill_encrypt(original_message)

    print("\nHill Ciphertext:", hill_ciphertext)

    # Authorization code
    authorization_code = int(input("Enter authorization code: "))

    if authorization_code >= p:
        print("Authorization code must be less than", p)
        return

    # ElGamal encryption
    authorization_ciphertext = elgamal_encrypt(authorization_code)

    print("ElGamal Public Key:", (p, g, y))
    print("ElGamal Ciphertext:", authorization_ciphertext)

    with open("transaction.txt", "w") as file:
        file.write(hill_ciphertext + "\n")
        file.write(str(authorization_ciphertext))


# Bank
def bank():
    if hill_ciphertext == "":
        print("No transaction available.")
        return

    # Hill decryption
    decrypted_message = hill_decrypt(hill_ciphertext)

    print("\nHill Ciphertext:", hill_ciphertext)
    print("Decrypted Transaction:", decrypted_message)

    # ElGamal decryption
    c1 = authorization_ciphertext[0]
    c2 = authorization_ciphertext[1]

    decrypted_code = elgamal_decrypt(c1, c2)

    print("ElGamal Decrypted Authorization Code:", decrypted_code)

    if decrypted_code == authorization_code:
        print("Authorization: VALID")
    else:
        print("Authorization: INVALID")
        
# Auditor
def auditor():
    print("Hill Ciphertext:", hill_ciphertext)
    print("ElGamal Public Key:", (p, g, y))
    print("ElGamal Ciphertext:", authorization_ciphertext)

    print("Hill Decryption: DENIED")
    print("Authorization Decryption: DENIED")
    print("Plaintext Access: DENIED")
    
while True:
    print("1. Customer")
    print("2. Bank")
    print("3. Auditor")
    print("0. Exit")

    choice = int(input("Enter role: "))

    if choice == 1:
        customer()

    elif choice == 2:
        bank()

    elif choice == 3:
        auditor()

    elif choice == 0:
        break

    else:
        print("Invalid choice.")