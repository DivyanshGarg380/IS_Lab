# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
A hospital must securely transfer a patient record using Diffie–Hellman key exchange and a manually implemented RSA algorithm. 
Use p=23, g=5, private values a=6, b=15, and RSA parameters p=11, q=13, e=7. 
Verify that both parties obtain the same shared secret, encrypt an integer patient ID using RSA, and verify the recovered ID.
'''

import math 
import hashlib 

ph,g,a,b = 23,5,6,15

A = pow(g,a,ph)
B = pow(g,b,ph)
key_sender = pow(B, a, ph)
key_receiver = pow(A, b, ph)

print("Sender Public Key:", A)
print("Receiver Public Key:", B)
print("Sender Shared Secret:", key_sender)
print("Receiver Shared Secret:", key_receiver)

if key_sender != key_receiver:
    print("Key exchange failed!")
    exit(0)
    
print("Shared secret verified!")

p,q = 11, 13
n = p * q 
phi = (p - 1) * (q - 1)
e = 7
d = pow(e, -1, phi)

print("\nRSA Public Key:", (e, n))
print("RSA Private Key:", (d, n))

patient_id = 42
ciphertext = pow(patient_id, e, n)

print("Original Patient ID:", patient_id)
print("Encrypted Patient ID:", ciphertext)

stored_hash = hashlib.sha256(str(ciphertext).encode()).hexdigest()

print("Stored SHA-256 Hash:", stored_hash)

received_ciphertext = ciphertext

received_hash = hashlib.sha256(str(received_ciphertext).encode()).hexdigest()

if received_hash != stored_hash:
    print("Integrity failed! Decryption denied.")
    exit(0)
    
print("Integrity verified!")

recovered_id = pow(received_ciphertext, d, n)

print("Decrypted Patient ID:", recovered_id)

if recovered_id == patient_id:
    print("Patient ID recovered successfully!")
else:
    print("Decryption failed!")


