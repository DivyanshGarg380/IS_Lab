# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248

# AES CTR MODE Ecryption and Decyption

from Crypto.Cipher import AES

plaintext = input("Enter plaintext: ")

key_hex = input("Enter key in hexa")
nonce_hex = input("Enter nonce in hexa")

key = bytes.fromhex(key_hex)
nonce = bytes.fromhex(nonce_hex)

cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
ciphertext = cipher.encrypt(plaintext.encode())
print("Ciphertext:", ciphertext.hex())

decipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
decrypted_text = decipher.decrypt(ciphertext)
print("Decrypted text:", decrypted_text.decode())

# CTR is a stream-like mode, so plaintext doesn't need block padding.