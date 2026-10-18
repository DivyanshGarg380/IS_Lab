# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
Use AES-128-CBC to encrypt a patient record held in a string. 
Encrypt the AES key using manually implemented RSA. 
Verify the ciphertext using SHA-256 before recovering the AES key and decrypting the record. Demonstrate tampering detection by modifying the ciphertext in memory.
'''

import hashlib 
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

patient_record = "Patient: Rahul, Blood Group: O+, Diagnosis: Fever"

aes_key = get_random_bytes(16)
cipher = AES.new(aes_key, AES.MODE_CBC)
iv = cipher.iv 
ciphertext = cipher.encrypt(pad(patient_record.encode()), AES.block_size)

p,q,e = 61,53,17
n = p * q
phi = (p-1)*(q-1)
d = pow(e, -1, phi)

encrypted_key = [pow(byte, e, n) for byte in aes_key]
print("Encrypted AES Key:", encrypted_key)
print("IV:", iv.hex())
print("Ciphertext:", ciphertext.hex())

stored_hash = hashlib.sha256(ciphertext).hexdigest()
print("Stored Hash:", stored_hash)

received_ciphertext = ciphertext

choice = input("Tamper with ciphertext? (yes/no): ").strip().lower()

if choice == "yes":
    modified = bytearray(received_ciphertext)
    modified[0] ^= 1
    received_ciphertext = bytes(modified)
    
received_hash = hashlib.sha256(received_ciphertext).hexdigest()

if received_hash != stored_hash:
    print("Integrity failed! Decryption denied.")
    exit(0)
    
print("Integrity verified!")

recovered_key = bytes(pow(value, d, n) for value in encrypted_key)

cipher = AES.new(recovered_key, AES.MODE_CBC, iv)

try:
    plaintext = unpad(cipher.decrypt(received_ciphertext),AES.block_size)

    print("Recovered AES Key:", recovered_key.hex())
    print("Patient Record:", plaintext.decode())

except ValueError:
    print("Decryption failed!")
