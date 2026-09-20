# AES-192 Ecryption and Decryption

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

plaintext = input("Enter plaintext: ")
key_hex = input("Enter key in hexa: ")

# convert to bytes
key = bytes.fromhex(key_hex)

if len(key) != 24:
    print("Error: AES-128 key must be 16 bytes.")
    exit()

# Encrypt    
cipher = AES.new(key, AES.MODE_ECB)

padded_text = pad(plaintext.encode(), AES.block_size)
ciphertext = cipher.encrypt(padded_text)
print("Encrypted data:", ciphertext.hex())

# Decrypt

decipher = AES.new(key, AES.MODE_ECB)
decrypted_padded = decipher.decrypt(ciphertext)
decrypted_text = unpad(decrypted_padded, AES.block_size)
print("Decrypted text:", decrypted_text.decode())

