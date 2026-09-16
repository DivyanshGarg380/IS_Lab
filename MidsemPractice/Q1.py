# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    MediSecure
    - Hospital Patient Record Management System
    - IT-B Question
'''

from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad, unpad
from sympy import randprime, gcd, mod_inverse
import hashlib 
import json
import os
from datetime import datetime 

DATABASE_FILE = "medisecure_records.json"
record = []

## RSA Key Generation
p = int(randprime(1000, 5000))
q = int(randprime(1000, 5000))

while p == q:
    q = int(randprime(1000, 5000))
    
n = p * q
phi = (p - 1) * (q - 1)
e = 3
while gcd(e, phi) != 1:
    e += 2
    
d = mod_inverse(e, phi) 

def load_records():
    global records 
    if os.path.exists(DATABASE_FILE):
        with open(DATABASE_FILE, "r") as file:
            records = json.load(file)
            
    else:
        records = []
        
        
def save_records():
    with open(DATABASE_FILE, "w") as file:
        json.dump(records, file, indent = 4)
        
        
# SHA-256 HASH
def sha256_hash(data):
    return hashlib.sha256(data).hexdigest()

# RSA digital signature 
def sign_hash(hash_value):
    # Convert hexa hash to decimal integer
    hash_int = int(hash_value, 16)
    
    # RSA signature
    sign = pow(hash_int, d, n)
    return sign 

# RSA signature verification
def verify_signature(sign, hash_val):
    # Convert hexa hash to decimal
    hash_int = int(hash_val, 16)
    
    verified_hash = pow(int(sign), e, n)
    
    return verified_hash == (hash_int % n)

# Patient
def patient():
    filename = input("Enter .txt file name: ")
    if not os.path.exists(filename):
        print("File does not exist")
        return 
    
    # Read medical records
    with open(filename, "rb") as file:
        data = file.read()
        
    # Get AES key from user
    key_hex = input(
        "Enter AES key in hexadecimal "
        "(32/48/64 hex characters): "
    )
    
    try:
        key = bytes.fromhex(key_hex)
        
    except ValueError:
        print("Invalid hexadecimal key.")
        return
    
    if len(key) not in [16, 24, 32]:
        print("AES key must be 128, 192 or 256 bits")
        return 
    
    
    # Ger IV from user
    iv_hex = input(
        "Enter IV in hexadecimal "
        "(32 hex characters): "
    )
    
    try:
        iv = bytes.fromhex(iv_hex)

    except ValueError:
        print("Invalid hexadecimal IV.")
        return

    if len(iv) != 16:
        print("IV must be exactly 16 bytes.")
        return
    
    cipher = AES.new(key, AES.MODE_CBC, iv)

    ciphertext = cipher.encrypt(
        pad(data, AES.block_size)
    )

    print("\nAES Encryption Successful")

    print("Encrypted Record (HEX):")
    print(ciphertext.hex())
    
    # SHA-256 of encrypted record
    encrypted_hash = sha256_hash(ciphertext)
    print("\nSHA-256 Hash of Encrypted Record:")
    print(encrypted_hash)
    
    # RSA Digital Signature
    sign = sign_hash(encrypted_hash)
    
    print("\nDigital Signature:")
    print(sign)
    
    # TimeStamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Store encrypted records seperately
    encrypted_filename = filename + ".enc"
    with open(encrypted_filename, "wb") as file:
        file.write(ciphertext)
        
    # Store record metadata
    record = {
        "filename": filename,
        "encrypted_file": encrypted_filename,
        "encrypted_record": ciphertext.hex(),
        "hash": encrypted_hash,
        "signature": str(sign),
        "iv": iv.hex(),
        "timestamp": timestamp
    }
    
    records.append(record)
    save_records()
    print("\nRecord uploaded successfully.")
    print("Timestamp:", timestamp)


def patient_view_records():
    if len(records) == 0:
        print("No records available.")
        return

    for i, record in enumerate(records):
        print("\nRecord", i + 1)
        print("Filename :", record["filename"])
        print("Hash :", record["hash"])
        print("Timestamp:", record["timestamp"])
    
    
# Doctor
def doctor():
    if len(records) == 0:
        print("No records available.")
        return
    
    # Display available records
    for i, record in enumerate(records):
        print(
            i + 1,
            ".",
            record["filename"],
            "|",
            record["timestamp"]
        )
        
    choice = int(input("\nSelect record: "))

    if choice < 1 or choice > len(records):
        print("Invalid record.")
        return

    record = records[choice - 1]
    
    # Get AES key
    key_hex = input(
        "\nEnter shared AES key in hexadecimal: "
    )
    
    try:
        key = bytes.fromhex(key_hex)

    except ValueError:
        print("Invalid AES key.")
        return

    if len(key) not in [16, 24, 32]:
        print("Invalid AES key size.")
        return
    
    # Get IV from stored record
    iv = bytes.fromhex(record["iv"])
    
    encrypted_file = record["encrypted_file"]

    if os.path.exists(encrypted_file):
        with open(encrypted_file, "rb") as file:
            ciphertext = file.read()
            
    # SHA integrity check
    calculated_hash = sha256_hash(ciphertext)

    print("\nStored SHA-256:")
    print(record["hash"])

    print("\nCalculated SHA-256:")
    print(calculated_hash)

    if calculated_hash != record["hash"]:
        print("\nSHA-256 Integrity: INVALID")
        print("Possible tampering detected.")
        print("Decryption NOT performed.")

        verification = {
            "filename": record["filename"],
            "result": "INTEGRITY FAILED",
            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        }

        with open("verification_results.txt", "a") as file:
            file.write(
                json.dumps(verification) + "\n"
            )

        return

    print("\nSHA-256 Integrity: VALID")
    
    # RSA digital signature verification
    if verify_signature(
        record["signature"],
        calculated_hash
    ):

        print("RSA Digital Signature: VALID")
        print("Patient Authenticity: VERIFIED")

    else:

        print("RSA Digital Signature: INVALID")
        print("Patient Authenticity: FAILED")
        print("Decryption NOT performed.")

        verification = {
            "filename": record["filename"],
            "result": "SIGNATURE FAILED",
            "timestamp": datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        }
        
        with open("verification_results.txt", "a") as file:
            file.write(
                json.dumps(verification) + "\n"
            )

        return
    
    # AES Decryption
    try:
        decipher = AES.new(
            key,
            AES.MODE_CBC,
            iv
        )

        decrypted = unpad(
            decipher.decrypt(ciphertext),
            AES.block_size
        )

    except Exception:
        print("\nAES Decryption Failed.")
        print("Wrong AES key or corrupted data.")
        return
    
    # Verify Decrypted Record
    decrypted_hash = sha256_hash(decrypted)

    print("\nSHA-256 of Decrypted Record:")
    print(decrypted_hash)
    
    # Display Plaintext
    try:
        print(decrypted.decode())

    except UnicodeDecodeError:
        print(decrypted)
        
    
    verification = {
        "filename": record["filename"],
        "integrity": "VALID",
        "signature": "VALID",
        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    }

    with open("verification_results.txt", "a") as file:
        file.write(
            json.dumps(verification) + "\n"
        )

    print("\nVerification result stored.")
    
def doctor_view_records():
    if len(records) == 0:
        print("No records available.")
        return

    for i, record in enumerate(records):
        print(
            f"{i + 1}. {record['filename']} "
            f"| Timestamp: {record['timestamp']}"
        )
        
# Auditor
def auditor():
    if len(records) == 0:
        print("No records available.")
        return

    for i, record in enumerate(records):
        print("\nRecord", i + 1)
        print("Filename :", record["filename"])
        print("SHA-256  :", record["hash"])
        print("Timestamp:", record["timestamp"])

    # Select record for signature verification
    choice = int(input("\nSelect record to verify signature: "))

    if choice < 1 or choice > len(records):
        print("Invalid choice.")
        return

    record = records[choice - 1]
    
    if verify_signature(
        record["signature"],
        record["hash"]
    ):

        print("\nRSA Digital Signature: VALID")
        print("Patient Authenticity: VERIFIED")

    else:

        print("\nRSA Digital Signature: INVALID")
        print("Patient Authenticity: FAILED")
        
    print("\nAuditor Access:")
    print("Decryption: NOT ALLOWED")
    print("Plaintext Medical Record: NOT ALLOWED")
    
def main():

    load_records()

    while True:
        print("\n")
        print("1. Patient")
        print("2. Doctor")
        print("3. Auditor")
        print("4. View Uploaded Records")
        print("0. Exit")

        try:
            choice = int(input("Enter role: "))

        except ValueError:
            print("Enter a valid number.")
            continue

        if choice == 1:

            while True:
                print("1. Upload and Encrypt Record")
                print("2. View Previous Records")
                print("0. Back")
                option = int(input("Enter choice: "))

                if option == 1:
                    patient()

                elif option == 2:
                    patient_view_records()

                elif option == 0:
                    break

                else:
                    print("Invalid choice.")

        elif choice == 2:
            while True:
                print("1. View Available Records")
                print("2. Decrypt and Verify Record")
                print("0. Back")
                option = int(input("Enter choice: "))
                if option == 1:
                    doctor_view_records()

                elif option == 2:
                    doctor()

                elif option == 0:
                    break

                else:
                    print("Invalid choice.")

        elif choice == 3:
            auditor()

        elif choice == 4:
            print("\nAccess controlled.")
            print(
                "Please select Patient, Doctor or Auditor role."
            )

        elif choice == 0:
            print("\nExiting MediSecure...")
            break

        else:
            print("Invalid role.")


if __name__ == "__main__":
    main()