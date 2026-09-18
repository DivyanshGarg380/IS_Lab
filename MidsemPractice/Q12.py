# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    MedVault — Hill + Rabin + SHA-256 + RBAC
        - Roles: Doctor, Nurse, Admin
        - Doctor: enter patient ID + diagnosis → Hill encrypt → Rabin encrypt each ciphertext character → SHA-256 → store.
        - Nurse: view Rabin ciphertext + hash → verify SHA-256.
        - Admin: view ID + hash + timestamp → verify SHA-256.
        - Doctor: verify hash → Rabin decrypt → Hill decrypt → display plaintext.
        - Given Hill matrix: [[3,3],[2,5]]
        - Given Rabin: p=11, q=13
        - Use uppercase alphabetic plaintext.
'''

import hashlib
from datetime import datetime 

key = [[3, 3], [2, 5]]

p = 11
q = 13
n = p * q

records = []

def hill_encrypt(text):
    text = text.upper().replace(" ", "")

    if len(text) % 2 != 0:
        text += "X"

    result = ""
    for i in range(0, len(text), 2):
        a = ord(text[i]) - ord('A')
        b = ord(text[i + 1]) - ord('A')

        x = (key[0][0] * a + key[0][1] * b) % 26
        y = (key[1][0] * a + key[1][1] * b) % 26

        result += chr(x + ord('A'))
        result += chr(y + ord('A'))

    return result

def hill_decrypt(text):
    det = (key[0][0] * key[1][1] - key[0][1] * key[1][0]) % 26
    det_inv = pow(det, -1, 26)

    inv = [
        [(key[1][1] * det_inv) % 26, (-key[0][1] * det_inv) % 26],
        [(-key[1][0] * det_inv) % 26, (key[0][0] * det_inv) % 26]
    ]

    result = ""

    for i in range(0, len(text), 2):
        a = ord(text[i]) - ord('A')
        b = ord(text[i + 1]) - ord('A')

        x = (inv[0][0] * a + inv[0][1] * b) % 26
        y = (inv[1][0] * a + inv[1][1] * b) % 26

        result += chr(x + ord('A'))
        result += chr(y + ord('A'))

    return result

def rabin_encrypt(text):
    encrypted = []

    for ch in text:
        value = ord(ch)
        encrypted.append((value * value) % n)

    return encrypted

def rabin_decrypt(encrypted):
    result = ""
    for c in encrypted:
        found = False
        for x in range(65, 91):
            if (x * x) % n == c:
                result += chr(x)
                found = True
                break

        if not found:
            return ""

    return result

def calculate_hash(data):
    return hashlib.sha256(str(data).encode()).hexdigest()

# Doctor

def add_record():
    patient_id = input("Enter Patient ID: ")
    diagnosis = input("Enter Diagnosis: ")

    plaintext = diagnosis.upper().replace(" ", "")

    hill_cipher = hill_encrypt(plaintext)

    rabin_cipher = rabin_encrypt(hill_cipher)

    hash_value = calculate_hash(rabin_cipher)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    record = {
        "ID": patient_id,
        "Ciphertext": rabin_cipher,
        "Hash": hash_value,
        "Timestamp": timestamp
    }

    records.append(record)

    print("Record stored successfully.")
    print("Patient ID:", patient_id)
    print("Hill Ciphertext:", hill_cipher)
    print("Rabin Ciphertext:", rabin_cipher)
    print("SHA-256:", hash_value)
    print("Timestamp:", timestamp)

def doctor_view():
    for record in records:
        print("\nPatient ID:", record["ID"])
        print("Rabin Ciphertext:", record["Ciphertext"])
        print("SHA-256:", record["Hash"])
        print("Timestamp:", record["Timestamp"])
        
def doctor_decrypt():
    patient_id = input("Enter Patient ID: ")

    for record in records:
        if record["ID"] == patient_id:
            current_hash = calculate_hash(record["Ciphertext"])

            if current_hash != record["Hash"]:
                print("Integrity: INVALID")
                return

            print("Integrity: VALID")

            hill_cipher = rabin_decrypt(record["Ciphertext"])

            if hill_cipher == "":
                print("Rabin Decryption Failed.")
                return

            plaintext = hill_decrypt(hill_cipher)

            print("Rabin Decrypted Data:", hill_cipher)
            print("Hill Decrypted Patient Information:", plaintext)
            return

    print("Record not found.")
    

# Nurse
def nurse_view():
    for record in records:
        print("\nPatient ID:", record["ID"])
        print("Rabin Ciphertext:", record["Ciphertext"])
        print("SHA-256:", record["Hash"])
        print("Timestamp:", record["Timestamp"])
        

def nurse_verify():
    patient_id = input("Enter Patient ID: ")

    for record in records:
        if record["ID"] == patient_id:
            current_hash = calculate_hash(record["Ciphertext"])

            if current_hash == record["Hash"]:
                print("Integrity: VALID")
            else:
                print("Integrity: INVALID")

            print("Verification Timestamp:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            return

    print("Record not found.")
    
    
# Admin
def admin_view():
    for record in records:
        print("\nPatient ID:", record["ID"])
        print("SHA-256:", record["Hash"])
        print("Timestamp:", record["Timestamp"])
        
def admin_verify():
    patient_id = input("Enter Patient ID: ")

    for record in records:
        if record["ID"] == patient_id:
            current_hash = calculate_hash(record["Ciphertext"])

            if current_hash == record["Hash"]:
                print("SHA-256: VALID")
            else:
                print("SHA-256: INVALID")

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
            print("1. Add Record")
            print("2. View Records")
            print("3. Decrypt Record")
            print("4. Back")

            choice = int(input("Enter choice: "))

            if choice == 1:
                add_record()

            elif choice == 2:
                doctor_view()

            elif choice == 3:
                doctor_decrypt()

            elif choice == 4:
                break

            else:
                print("Invalid choice.")

    elif role == 2:
        while True:
            print("1. View Encrypted Records")
            print("2. Verify Integrity")
            print("3. Back")

            choice = int(input("Enter choice: "))

            if choice == 1:
                nurse_view()

            elif choice == 2:
                nurse_verify()

            elif choice == 3:
                break

            else:
                print("Invalid choice.")

    elif role == 3:
        while True:
            print("1. View Record Information")
            print("2. Verify Integrity")
            print("3. Back")

            choice = int(input("Enter choice: "))

            if choice == 1:
                admin_view()

            elif choice == 2:
                admin_verify()

            elif choice == 3:
                break

            else:
                print("Invalid choice.")

    elif role == 4:
        print("Exiting MedVault...")
        break

    else:
        print("Invalid role.")
        
