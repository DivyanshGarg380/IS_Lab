# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    Hospital Based Management System
    - AES-128 -> File encryption
    - RSA -> AES key encryption
    - ElGamal -> Authorization code encryption
    - SHA-256 -> Integrity verification
'''

from sympy import randprime, mod_inverse, gcd 
import hashlib
import os 
from datetime import datetime 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

AES_KEY = b"0123456789ABCDEF"  
IV = b"1234567890123456" 

ciphertext = b""
original_hash = ""
encrypted_hash = ""
rsa_ciphertext = 0
elgamal_ciphertext = ()
elgamal_private_key = 0
elgamal_public_key = 0

# RSA Key Generation
p_rsa = 1009
q_rsa = 1013

n_rsa = p_rsa * q_rsa
phi_rsa = (p_rsa - 1) * (q_rsa - 1)
e_rsa = 65537
while gcd(e_rsa, phi_rsa) != 1:
    e_rsa += 2

d_rsa = mod_inverse(e_rsa, phi_rsa)

# Elgamal Parameters
elgamal_p = 467
elgamal_g = 2

# Private key
elgamal_x = 127

# Public key
elgamal_y = pow(
    elgamal_g,
    elgamal_x,
    elgamal_p
)

# Elgamal Encryption
def elgamal_encrypt(message):
    message = message % elgamal_p
    k = 3

    while gcd(k, elgamal_p - 1) != 1:
        k += 1

    c1 = pow(elgamal_g, k, elgamal_p)
    shared_secret = pow(elgamal_y, k, elgamal_p)

    c2 = (message * shared_secret) % elgamal_p
    return c1, c2

# Elgamal Decryption
def elgamal_decrypt(c1, c2):
    shared_secret = pow(c1, elgamal_x, elgamal_p)
    inverse_secret = pow(shared_secret, -1, elgamal_p)
    message = (c2 * inverse_secret) % elgamal_p
    return message

# RSA encryption of AES Key
def rsa_encrypt_aes_key(key):
    key_int = int.from_bytes(key)
    encrypted_key = pow(key_int, e_rsa, n_rsa)
    return encrypted_key

# RSA decryption of AES key
def rsa_decrypt_aes_key(encrypted_key):
    key_int = pow(encrypted_key, d_rsa, n_rsa)
    key = key_int.to_bytes(16,)
    return key

# Create file
def create_file():
    filename = input("Enter file name: ")
    content = input("Enter file content: ")

    with open(filename, "w") as file:
        file.write(content)

    print("File created successfully.")

# Encrypt file using AES-128
def encrypt_file():

    global ciphertext
    global original_hash
    global encrypted_hash
    global rsa_ciphertext
    global elgamal_ciphertext

    filename = input("Enter file name to encrypt: ")

    if not os.path.exists(filename):
        print("File does not exist.")
        return

    with open(filename, "rb") as file:
        data = file.read()

    print("\nOriginal File Content:")
    print(data.decode())


    original_hash = hashlib.sha256(data).hexdigest()

    print("\nSHA-256 of Original File:")
    print(original_hash)

    cipher = AES.new(AES_KEY, AES.MODE_CBC, IV)

    ciphertext = cipher.encrypt(
        pad(
            data,
            AES.block_size
        )
    )

    with open(
        "encrypted_message.txt",
        "wb"
    ) as file:
        file.write(ciphertext)
        
    print("\nAES Encrypted Message (HEX):")
    print(ciphertext.hex())

    encrypted_hash = hashlib.sha256(
        ciphertext
    ).hexdigest()

    print("\nSHA-256 of Encrypted Message:")
    print(encrypted_hash)

    rsa_ciphertext = rsa_encrypt_aes_key(AES_KEY)

    with open(
        "encrypted_aes_key.txt",
        "w"
    ) as file:
        file.write(
            str(rsa_ciphertext)
        )

    print("\nRSA Encrypted AES Key:")
    print(rsa_ciphertext)

    authorization_code = int(input("\nEnter Authorization Code: "))
    elgamal_ciphertext = elgamal_encrypt(authorization_code)

    print(
        "Encrypted Authorization Code (c1,c2):",
        elgamal_ciphertext
    )

    print("\nEncryption completed successfully.")
    
    
# Verify Integrity
def verify_integrity():
    global encrypted_hash

    if not os.path.exists(
        "encrypted_message.txt"
    ):
        print("Encrypted file does not exist.")
        return False

    with open(
        "encrypted_message.txt",
        "rb"
    ) as file:
        current_ciphertext = file.read()

    calculated_hash = hashlib.sha256(
        current_ciphertext
    ).hexdigest()

    print("\nSender Hash:")
    print(encrypted_hash)

    print("\nReceiver Calculated Hash:")
    print(calculated_hash)
    
    if calculated_hash == encrypted_hash:
        print("\nIntegrity: VALID")
        print("Sender and Receiver Hashes Match.")
        return True

    else:
        print("\nIntegrity: FAILED")
        print("Sender and Receiver Hashes Do NOT Match.")
        return False

# Decrypt File
def decrypt_file():
    global rsa_ciphertext
    global elgamal_ciphertext

    valid = verify_integrity()

    if not valid:
        print("\nERROR: File has been tampered with.")
        print("Decryption will NOT be performed.")
        return
    
    decrypted_aes_key = rsa_decrypt_aes_key(rsa_ciphertext)

    print("\nRSA Decrypted AES Key:")
    print(decrypted_aes_key.decode())
    
    c1, c2 = elgamal_ciphertext

    decrypted_authorization = elgamal_decrypt(c1,c2)
    print("\nElGamal Decrypted Authorization Code:")
    print(decrypted_authorization)
    
    with open(
        "encrypted_message.txt",
        "rb"
    ) as file:
        encrypted_data = file.read()
    
    decipher = AES.new(
        decrypted_aes_key,
        AES.MODE_CBC,
        IV
    )

    try:
        decrypted_data = unpad(
            decipher.decrypt(
                encrypted_data
            ),
            AES.block_size
        )

    except ValueError:
        print("\nAES Decryption Failed.")
        print("Invalid key, IV or ciphertext.")
        return
    
    print(
        "Decrypted AES Key:",
        decrypted_aes_key.decode())

    print("\nOriginal File Content:")

    print(decrypted_data.decode())
    
    decrypted_hash = hashlib.sha256(
        decrypted_data
    ).hexdigest()

    print(decrypted_hash)

    print(original_hash)

    if decrypted_hash == original_hash:
        print("\nOriginal File Integrity: VALID")

    else:
        print("\nOriginal File Integrity: INVALID")
        
        
# Tamper with AES cipher text
def tamper_file():
    if not os.path.exists(
        "encrypted_message.txt"
    ):

        print("Encrypted file does not exist.")
        return

    with open(
        "encrypted_message.txt",
        "rb"
    ) as file:
        data = bytearray(file.read())

    if len(data) == 0:
        print("Encrypted file is empty.")
        return

    # Modify one byte
    data[0] ^= 1

    with open(
        "encrypted_message.txt",
        "wb"
    ) as file:
        file.write(data)

    print("One character/byte of AES ciphertext modified.")

    print("Encrypted file has been tampered with.")

    tampered_hash = hashlib.sha256(
        bytes(data)
    ).hexdigest()

    print("\nOriginal Stored Hash:")
    print(encrypted_hash)
    
    print("\nTampered File Hash:")
    print(tampered_hash)

    if tampered_hash != encrypted_hash:
        print("\nIntegrity FAILED.")
        print("Tampering successfully detected.")
        
def display_values():
    print("\nAES-128 Key:")
    print(AES_KEY.decode())

    print("\nIV:")
    print(IV.decode())

    print("\nSHA-256 Original:")
    print(original_hash)

    print("\nSHA-256 Encrypted:")
    print(encrypted_hash)

    print("\nRSA Public Key:")
    print("n =", n_rsa)
    print("e =", e_rsa)

    print("\nRSA Encrypted AES Key:")
    print(rsa_ciphertext)

    print("\nElGamal Public Parameters:")
    print("p =", elgamal_p)
    print("g =", elgamal_g)
    print("y =", elgamal_y)

    print("\nElGamal Encrypted Authorization Code:")
    print(elgamal_ciphertext)

while True:

    print("\n")
    print("1. Create File")
    print("2. Encrypt File using AES-128")
    print("3. Display Stored/Public Values")
    print("4. Verify Integrity and Decrypt")
    print("5. Modify Ciphertext - Show Integrity Failure")
    print("0. Exit")

    try:
        choice = int(input("Enter choice: "))

    except ValueError:
        print("Enter a valid choice.")
        continue
    
    if choice == 1:
        create_file()

    elif choice == 2:
        encrypt_file()

    elif choice == 3:
        display_values()

    elif choice == 4:
        decrypt_file()

    elif choice == 5:
        tamper_file()

    elif choice == 0:
        print("Exiting Hospital Security System...")
        break

    else:
        print("Invalid choice.")