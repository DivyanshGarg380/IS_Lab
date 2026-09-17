# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    IT-C Question
    
    Refer LabXam for detailed question
'''

import hashlib
from datetime import datetime 

p = 61
q = 53
n = p * q
phi = (p - 1) * (q - 1)
e = 17
d = pow(e, -1, phi)
public_key = (e, n)
private_key = (d, n)

records = []

def rsa_encrypt(text, public_key):
    e, n = public_key
    encrypted = []

    for ch in text:
        encrypted.append(pow(ord(ch), e, n))

    return encrypted

def rsa_decrypt(encrypted, private_key):
    d, n = private_key
    text = ""

    for value in encrypted:
        text += chr(pow(value, d, n))

    return text

def calculate_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

# Doctor

def doctor_add_record():
    name = input("Enter Patient Name: ")
    age = input("Enter Age: ")
    gender = input("Enter Gender: ")
    blood = input("Enter Blood Group: ")
    diagnosis = input("Enter Diagnosis: ")
    details = input("Enter Other Medical Details: ")

    patient_data = {
        "Name": name,
        "Age": age,
        "Gender": gender,
        "Blood Group": blood,
        "Diagnosis": diagnosis,
        "Other Details": details
    }
    
    patient_string = str(patient_data)

    encrypted_data = rsa_encrypt(patient_string, public_key)

    encrypted_string = str(encrypted_data)

    hash_value = calculate_hash(encrypted_string)

    hash_int = int(hash_value, 16) % n

    signature = pow(hash_int, d, n)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    record = {
        "ID": len(records) + 1,
        "Name": name,
        "Encrypted": encrypted_data,
        "Hash": hash_value,
        "Signature": signature,
        "Timestamp": timestamp
    }

    records.append(record)

    print("Patient record stored successfully.")
    print("Record ID:", record["ID"])
    print("Timestamp:", timestamp)
    
def doctor_view_records():
    if len(records) == 0:
        print("No patient records available.")
        return

    for record in records:
        print("\nRecord ID:", record["ID"])
        print("Patient Name:", record["Name"])
        print("Encrypted Data:", record["Encrypted"])
        print("SHA-256 Hash:", record["Hash"])
        print("Digital Signature:", record["Signature"])
        print("Timestamp:", record["Timestamp"])
        
def doctor_decrypt():
    if len(records) == 0:
        print("No patient records available.")
        return

    record_id = int(input("Enter Record ID: "))

    for record in records:
        if record["ID"] == record_id:

            encrypted_string = str(record["Encrypted"])

            current_hash = calculate_hash(encrypted_string)

            if current_hash != record["Hash"]:
                print("INTEGRITY CHECK FAILED.")
                return

            print("Integrity Check: VALID")

            hash_int = int(current_hash, 16) % n

            verified_hash = pow(record["Signature"], e, n)

            if verified_hash != hash_int:
                print("RSA Signature: INVALID")
                return

            print("RSA Signature: VALID")

            decrypted_data = rsa_decrypt(record["Encrypted"], private_key)

            print("Decrypted Patient Information:", decrypted_data)
            print("Decryption successful.")
            return

    print("Record not found.")
    
    
# Nurse
def nurse_view_records():
    if len(records) == 0:
        print("No patient records available.")
        return

    for record in records:
        print("\nRecord ID:", record["ID"])
        print("Encrypted Data:", record["Encrypted"])
        print("SHA-256 Hash:", record["Hash"])
        print("Digital Signature:", record["Signature"])
        print("Timestamp:", record["Timestamp"])
        
def nurse_verify():
    if len(records) == 0:
        print("No patient records available.")
        return

    record_id = int(input("Enter Record ID: "))

    for record in records:
        if record["ID"] == record_id:
            encrypted_string = str(record["Encrypted"])

            current_hash = calculate_hash(encrypted_string)

            if current_hash == record["Hash"]:
                print("Integrity: VALID")
            else:
                print("Integrity: INVALID")

            hash_int = int(record["Hash"], 16) % n

            verified_hash = pow(record["Signature"], e, n)

            if verified_hash == hash_int:
                print("Authenticity: VALID")
            else:
                print("Authenticity: INVALID")

            print("Verification Timestamp:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            return

    print("Record not found.")

# Admin
def admin_view_records():
    if len(records) == 0:
        print("No patient records available.")
        return

    for record in records:
        print("\nRecord ID:", record["ID"])
        print("Patient Name:", record["Name"])
        print("SHA-256 Hash:", record["Hash"])
        print("Timestamp:", record["Timestamp"])
        
        
def admin_verify():
    if len(records) == 0:
        print("No patient records available.")
        return

    record_id = int(input("Enter Record ID: "))

    for record in records:
        if record["ID"] == record_id:
            hash_int = int(record["Hash"], 16) % n

            verified_hash = pow(record["Signature"], e, n)

            if verified_hash == hash_int:
                print("Digital Signature: VALID")
            else:
                print("Digital Signature: INVALID")

            return

    print("Record not found.")
    
while True:
    print("1. Doctor")
    print("2. Nurse")
    print("3. Admin")
    print("4. Exit")

    role = int(input("Enter Role: "))

    if role == 1:
        while True:
            print("1. Add Patient Record")
            print("2. View Patient Records")
            print("3. Decrypt Patient Record")
            print("4. Back")

            choice = int(input("Enter choice: "))

            if choice == 1:
                doctor_add_record()

            elif choice == 2:
                doctor_view_records()

            elif choice == 3:
                doctor_decrypt()

            elif choice == 4:
                break

            else:
                print("Invalid choice.")
                
    elif role == 2:
        while True:
            print("1. View Encrypted Records")
            print("2. Verify Integrity and Authenticity")
            print("3. Back")

            choice = int(input("Enter choice: "))

            if choice == 1:
                nurse_view_records()

            elif choice == 2:
                nurse_verify()

            elif choice == 3:
                break

            else:
                print("Invalid choice.")
                
                
    elif role == 3:
        while True:
            print("1. View Record Information")
            print("2. Verify Digital Signature")
            print("3. Back")

            choice = int(input("Enter choice: "))

            if choice == 1:
                admin_view_records()

            elif choice == 2:
                admin_verify()

            elif choice == 3:
                break

            else:
                print("Invalid choice.")
                
                
    elif role == 4:
        print("Exiting")
        break

    else:
        print("Invalid role.")