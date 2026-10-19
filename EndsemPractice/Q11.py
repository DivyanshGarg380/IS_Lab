# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
A research centre stores patients' integer test scores using Paillier encryption. 
Encrypt three scores, compute their encrypted sum without decrypting individual scores, and verify the integrity of the encrypted aggregate using SHA-256. 
If the ciphertext is altered, reject the result; otherwise, decrypt the sum and verify it against the expected total.
'''

import hashlib
from phe import paillier 

public_key, private_key = paillier.generate_paillier_keypair()

scores = [65, 78, 91]
encrypted_scores = [public_key.encrypt(s) for s in scores]

print("Encrypted scores:")
for c in encrypted_scores:
    print(c.ciphertext())
    
encrypted_sum = encrypted_scores[0]
for c in encrypted_scores[1:]:
    encrypted_sum += c 
    
aggregate_ciphertext = encrypted_sum.ciphertext()
print("\nEncrypted aggregate:", aggregate_ciphertext)

stored_hash = hashlib.sha256(str(aggregate_ciphertext).encode()).hexdigest()
print("Stored SHA-256:", stored_hash)

received_ciphertext = aggregate_ciphertext

choice = input("Tamper with aggregate? (yes/no): ").strip().lower()

if choice == "yes":
    received_ciphertext = (received_ciphertext + 1) % (public_key.n ** 2)

received_hash = hashlib.sha256(str(received_ciphertext).encode()).hexdigest()

if received_hash != stored_hash:
    print("Integrity failed! Aggregate rejected.")
else:
    print("Integrity verified!")

    received_encrypted_sum = paillier.EncryptedNumber(public_key, received_ciphertext)

    total = private_key.decrypt(received_encrypted_sum)
    expected_total = sum(scores)

    print("Decrypted total:", total)
    print("Expected total:", expected_total)

    if total == expected_total:
        print("Aggregate verified successfully!")
    else:
        print("Aggregate result mismatch!")
