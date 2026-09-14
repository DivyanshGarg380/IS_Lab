# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248

# TRIPLE DES ENCRYPTION AND DECRYPTION

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

plaintext = input("Enter plaintext: ")
key_hex = input("Enter 3DES key in hexadecimal: ")

key = bytes.fromhex(key_hex)

if len(key) not in [16, 24]:
    print("INvalid Key")
    exit()
    
cipher = DES3.new(key, DES3.MODE_ECB)
padded_text = pad(plaintext.encode(), DES3.block_size)
ciphertext = cipher.encrypt(padded_text)
print("Encrypted data:", ciphertext.hex())

decipher = DES3.new(key, DES3.MODE_ECB)
decrypted_padded = decipher.decrypt(ciphertext)
decrypted_text = unpad(decrypted_padded, DES3.block_size)
print("Decrypted text:", decrypted_text.decode())

