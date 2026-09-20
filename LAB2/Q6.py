# DES BLOCK DATA Ecryption and Decryption

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

key_hex = "A1B2C3D4E5F60708"

block1_hex = "54686973206973206120636f6e666964656e7469616c206d657373616765"
block2_hex = "416e64207468697320697320746865207365636f6e6420626c6f636b"

key = bytes.fromhex(key_hex)

block1 = bytes.fromhex(block1_hex)
block2 = bytes.fromhex(block2_hex)

cipher = DES.new(key, DES.ECB_MODE)

ciphertext1 = cipher.encrypt(block1)
ciphertext2 = cipher.encrypt(block2)

print("Ciphertext Block 1:", ciphertext1.hex())
print("Ciphertext Block 2:", ciphertext2.hex())

print("Ciphertext Block 1:", ciphertext1.hex())
print("Ciphertext Block 2:", ciphertext2.hex())
