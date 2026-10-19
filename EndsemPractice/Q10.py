# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
A hospital stores a medical report and its RSA digital signature. 
Implement RSA key generation, signing and verification manually using p=17, q=11, e=7. 
Sign the SHA-256 digest of the report using the private key. 
The Doctor may view the report, while the Auditor may only verify the signature and must not access the report. 
Detect tampering if the report changes before verification.
'''

import hashlib 
import math 

p,q = 17,11
n = p * q
phi = (p-1)*(q-1)
e = 7
d = pow(e, -1, phi)

public_key = (e, n)
private_key = (d, n)

print("Public Key:", public_key)

report = input("Enter medical report: ")

def hash_report(text):
    digest = hashlib.sha256(text.encode()).digest()
    return int.from_bytes(digest, "big")

digest = hash_report(report)

signature = pow(digest % n, d, n)
print("Digital Signature:", signature)


received_report = report
choice = input("Modify report before verification? (yes/no): ").strip().lower()

if choice == "yes":
    received_report += " TAMPERED"
    
role = input("Enter role (Doctor/Auditor): ").strip().lower()

received_digest = hash_report(received_report)
verified_digest = pow(signature, e, n)

signature_valid = (received_digest % n == verified_digest)

print("Signature Status:", "VALID" if signature_valid else "INVALID")

if role == "doctor":
    if signature_valid:
        print("Report authenticated.")
        print("Medical Report:", received_report)
    else:
        print("Report modified! Access denied.")

elif role == "auditor":
    print("Auditor can verify signatures but cannot view reports.")
    print("Report content access denied.")

else:
    print("Invalid role! Access denied.")
