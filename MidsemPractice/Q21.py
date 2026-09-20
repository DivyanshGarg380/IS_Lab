# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    SecureVault – Secure Record Management System

    Design and implement an application named "SecureVault" for securely storing, authenticating, accessing, and auditing confidential client records. The application must have three roles: Client, Lawyer, and Compliance Officer.

    The application must use:
    1. DES in CBC mode for encryption and decryption.
    2. SHA-256 for data integrity verification.
    3. ElGamal Digital Signature for authentication and verification.

    CLIENT:

    The Client should:
    1. Enter/provide a confidential record.
    2. Encrypt the record using DES in CBC mode.
    3. Generate an IV and use it during encryption.
    4. Calculate the SHA-256 hash of the encrypted data.
    5. Generate an ElGamal digital signature using the client's private key.
    6. Display the following:
        - Ciphertext
        - IV
        - SHA-256 hash value
        - ElGamal signature
        - Timestamp
    7. Store the ciphertext, IV, hash value, signature, and timestamp in a file for future verification and access.

    LAWYER:

    The Lawyer should:
    1. Read the stored ciphertext, IV, hash value, signature, and timestamp from the file.
    2. Recalculate the SHA-256 hash and compare it with the stored hash value.
    3. Verify the ElGamal digital signature using the client's public key.
    4. Display the hash verification and signature verification status.
    5. Only if the hash and signature verification are successful, decrypt the ciphertext using DES in CBC mode.
    6. Display the recovered plaintext record.
    7. Store the verification/access status along with a timestamp.

    If the integrity or signature verification fails, the Lawyer must not decrypt or access the plaintext.

    COMPLIANCE OFFICER:

    The Compliance Officer should:
    1. Access the stored encrypted record and its associated security metadata.
    2. Verify the SHA-256 hash to check whether the stored data has been modified.
    3. Verify the ElGamal digital signature using the client's public key.
    4. Display the hash verification and signature verification status.
    5. Record the verification results along with a timestamp.
    6. Generate a Compliance Report containing the verification status and relevant metadata.
    7. The Compliance Officer must NOT decrypt the ciphertext or access the client's plaintext record.

    The application should maintain proper role-based access, ensuring that:
        - The Client can create and securely store records.
        - The Lawyer can verify and decrypt records after successful authentication.
        - The Compliance Officer can independently audit the record's integrity and authenticity without accessing the plaintext.

    The system should clearly display all relevant security information and verification results.
'''

# IT-B question as of 18/09/2026

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import hashlib 
import os 
from datetime import datetime 

# Elgamal Params
p = 467
g = 2
x = 127
y = pow(g, x, p)
k = 5

metadata_file = "securevault.txt"
report_file = "compliance_report.txt"
verification_file = "verification.txt"

# Client
def client():
    record = input("Enter Confidential record: ")
    key = input("Enter DES key").encode()
    iv = b"A1B2C3D4"
    
    cipher = DES.new(key, DES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(record.encode(), DES.block_size))
    
    hash_val = hashlib.sha256(encrypted).hexdigest()
    hash_int = int(hash_val, 16) % p
    
    r = pow(g, k, p)
    k_inv = pow(k, -1, p - 1)
    s = ((hash_int - x * r) * k_inv) % (p - 1)
    signature = (r, s)
    
    timestamp = str(datetime.now())
    
    print("\nCiphertext:")
    print(encrypted.hex())

    print("\nIV:")
    print(iv.hex())

    print("\nSHA-256:")
    print(hash_val)

    print("\nElGamal Signature:")
    print(signature)

    print("\nTimestamp:")
    print(timestamp)
    
    with open(metadata_file, "a") as f:
        f.write(encrypted.hex() + "\n")
        f.write(iv.hex() + "\n")
        f.write(hash_val + "\n")
        f.write(str(r) + "\n")
        f.write(str(s) + "\n")
        f.write(timestamp + "\n")
        
    print("\nRecord stored successfully.")

# Lawyer
def lawyer():
    records = []
    with open(metadata_file, "r") as f:
        while True:
            encrypted_data = f.readline().strip()
            
            if encrypted_data == "":
                break 
            
            iv = f.readline().strip()
            hash_value = f.readline().strip()
            c1 = int(f.readline().strip())
            c2 = int(f.readline().strip())
            timestamp = f.readline().strip()
            
            records.append(
                (encrypted_data, iv, hash_value, c1, c2, timestamp)
            )
            
            print(len(records), ". Timestamp:", timestamp)
    
    choice = int(input("Select Record: "))
    encrypted_data, iv, hash_value, c1, c2, timestamp = records[choice-1]
    encrypted = bytes.fromhex(encrypted_data)
    iv = bytes.fromhex(iv)
    
    current_hash = hashlib.sha256(encrypted).hexdigest()

    print("\nStored Hash:")
    print(hash_value)

    print("\nCurrent Hash:")
    print(current_hash)

    if current_hash == hash_value:
        print("\nHash Verification: SUCCESS")
    else:
        print("\nHash Verification: FAILED")
        print("Decryption not performed.")
        return
    
    h = int(hash_value, 16)
    left = (pow(y, c1, p) * pow(c1, c2, p)) % p
    right = pow(g, h, p)

    if left == right:
        print("Signature Verification: SUCCESS")
    else:
        print("Signature Verification: FAILED")
        print("Decryption not performed.")
        return
    
    key = input("\nEnter DES key: ").encode()

    cipher = DES.new(key, DES.MODE_CBC, iv)

    decrypted = unpad(cipher.decrypt(encrypted), DES.block_size).decode()

    print("\nRecovered Plaintext:")
    print(decrypted)

    verify_time = str(datetime.now())

    with open(verification_file, "a") as f:
        f.write("Lawyer - Hash: VALID, Signature: VALID\n")
        f.write("Access Timestamp: " + verify_time + "\n")

    print("\nVerification/Access status stored.")
    
# Compliance Officer
def compliance():
     with open(metadata_file, "r") as f:
        while True:
            encrypted_data = f.readline().strip()

            if encrypted_data == "":
                break

            iv = f.readline().strip()
            hash_value = f.readline().strip()
            c1 = int(f.readline().strip())
            c2 = int(f.readline().strip())
            timestamp = f.readline().strip()

            encrypted = bytes.fromhex(encrypted_data)

            print("\nTimestamp:", timestamp)
            print("SHA-256:", hash_value)
            print("ElGamal Signature:", (c1, c2))

            current_hash = hashlib.sha256(encrypted).hexdigest()

            if current_hash == hash_value:
                hash_status = "VALID"
                print("Hash Verification: VALID")
            else:
                hash_status = "INVALID"
                print("Hash Verification: INVALID")

            h = int(hash_value, 16)
            left = (pow(y, c1, p) * pow(c1, c2, p)) % p
            right = pow(g, h, p)

            if left == right:
                signature_status = "VALID"
                print("Signature Verification: VALID")
            else:
                signature_status = "INVALID"
                print("Signature Verification: INVALID")

            report_time = str(datetime.now())

            with open(report_file, "a") as report:
                report.write("Timestamp: " + timestamp + "\n")
                report.write("SHA-256: " + hash_value + "\n")
                report.write("Hash Verification: " + hash_status + "\n")
                report.write("Signature Verification: " + signature_status + "\n")
                report.write("Report Generated: " + report_time + "\n")
                report.write("\n")

            print("\nCompliance report generated.")
            print("Compliance Officer cannot decrypt the record.")           
            
while True:
    print("1. Client")
    print("2. Lawyer")
    print("3. Compliance Officer")
    print("4. Exit")

    role = int(input("Enter role: "))

    if role == 1:
        client()

    elif role == 2:
        lawyer()

    elif role == 3:
        compliance()

    elif role == 4:
        print("Exiting...")
        break

    else:
        print("Invalid role.")