# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248

# DES vs AES-256 PERFORMANCE

from Crypto.Cipher import AES, DES 
from Crypto.Util.Padding import pad, unpad
import time 

plaintext = b"Performance Testing of Encryption Algorithms"

# DES

# Encrypt
des_key = b"A1B2C3D4"
start = time.time()

des_cipher = DES.new(des_key, DES.MODE_ECB)
des_ciphertext = des_cipher.encrypt(pad(plaintext, DES.block_size))

des_encryption_time = time.time() - start

# Decrypt
start = time.time()
des_decipher = DES.new(des_key, DES.MODE_ECB)
des_padded_plaintext = des_decipher.decrypt(des_ciphertext)
des_plaintext = unpad(des_padded_plaintext, DES.block_size)
des_decryption_time = time.time() - start

# AES

# Encrypt
aes_key = b"0123456789ABCDEF0123456789ABCDEF"
start = time.time()
aes_cipher = AES.new(aes_key, AES.MODE_ECB)
aes_ciphertext = aes_cipher.encrypt(pad(plaintext, AES.block_size))
aes_encryption_time = time.time() - start

# Decrypt
start = time.time()
aes_decipher = AES.new(aes_key, AES.MODE_ECB)
aes_padded_plaintext = aes_decipher.decrypt(aes_ciphertext)
aes_plaintext = unpad(aes_padded_plaintext, AES.block_size)
aes_decryption_time = time.time() - start

print("\nPerformance Comparison")

print("DES Encryption Time :", des_encryption_time)
print("DES Decryption Time :", des_decryption_time)

print("AES-256 Encryption Time :", aes_encryption_time)
print("AES-256 Decryption Time :", aes_decryption_time)