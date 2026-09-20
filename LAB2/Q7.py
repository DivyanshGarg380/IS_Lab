# DES CBC MODE Ecryption and Decryption

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

plaintext = input("Enter plaintext: ")
key = b"A1B2C3D4"
iv = b"12345678"

cipher = DES.new(key, DES.MODE_CBC, iv)
padded_text = pad(plaintext.encode(), DES.block_size)
ciphertext = cipher.encrypt(padded_text)
print("Ciphertext:", ciphertext.hex())


decipher = DES.new(key, DES.MODE_CBC, iv)
decrypted_text = unpad(decipher.decrypt(ciphertext), DES.block_size)
print("Decrypted text:", decrypted_text.decode())

