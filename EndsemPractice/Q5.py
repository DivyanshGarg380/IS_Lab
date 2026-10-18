# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
Implement Paillier encryption using the phe library to encrypt two medical bills, 
perform homomorphic addition without decrypting individual bills, and verify the final bill using SHA-256 hashing.
'''

from phe import paillier
import hashlib 

public_key, private_key = paillier.generate_paillier_keypair()

bill1, bill2 = 500, 800

encrypted1 = public_key.encrypt(bill1)
encrypted2 = public_key.encrypt(bill2)

print("Encrypted Bill 1:", encrypted1.ciphertext())
print("Encrypted Bill 2:", encrypted2.ciphertext())

encrypted_total = encrypted1 + encrypted2
print("\nEncrypted Total:", encrypted_total.ciphertext())

ciphertext = str(encrypted_total.ciphertext())
stored_hash = hashlib.sha256(ciphertext.encode()).hexdigest()
print("Stored Hash:", stored_hash)

received_hash = hashlib.sha256(str(encrypted_total.ciphertext()).encode()).hexdigest()

if received_hash == stored_hash:
    print("Integrity Verified!")
    total = private_key.decrypt(encrypted_total)
    print("Final Medical Bill:", total)
else:
    print("Integrity Failed! Decryption Denied.")

