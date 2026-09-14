# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248

# DES Ecryption and Decryption

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

plaintext = input("Enter plaintext: ")
key = input("Enter DES Key: ").encode()

if len(key) != 8:
    print("Error: DES key must be exactly 8 characters.")
    exit()
    
    
cipher = DES.new(key, DES.MODE_ECB)

# Encrypt
padded_text = pad(plaintext.encode(), DES.block_size)
ciphertext = cipher.encrypt(padded_text)
print("Encrypted data:", ciphertext.hex())

# Decrypt
decipher = DES.new(key, DES.MODE_ECB)
decrypted_padded = decipher.decrypt(ciphertext)

# Remove padding
decrypted_text = unpad(decrypted_padded, DES.block_size)
print("Decrypted text:", decrypted_text.decode())

