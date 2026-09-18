# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    SecureMed — Playfair + AES-CBC + RSA Signature + SHA-256 + RBAC

    - Roles: Doctor, Nurse, Admin

    - Doctor: enter patient record → Playfair encrypt → AES-128-CBC encrypt → SHA-256 AES ciphertext → RSA-sign hash → store everything.
    - Nurse: verify hash + RSA signature → if valid, AES-decrypt only and display Playfair ciphertext. Must NOT obtain plaintext.
    - Admin: view Record ID + hash + timestamp → verify RSA signature → revoke/disable a record. Cannot decrypt.
    - Doctor: verify hash + signature → AES decrypt → Playfair decrypt → display plaintext.
    - Tampering option: modify one byte of stored AES ciphertext.
    - Use RBAC.
'''

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime
import hashlib

p = 61
q = 53
e = 17
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
public_key = (e, n)
private_key = (d, n)

PLAYFAIR_KEY = "MEDICAL"
AES_KEY = b"1234567890ABCDEF"
IV = b"ABCDEF1234567890"

records = []

def create_matrix(key):
  alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
  used = ""
  for ch in key.upper():
    if ch == "J":
      ch = "I"
    if ch.isalpha() and ch not in used:
      used += ch

  for ch in alphabet:
    if ch not in used:
      used += ch

  matrix = []
  for i in range(0, 25, 5):
    matrix.append(list(used[i : i + 5]))

  return matrix

def find_position(matrix, ch):
  if ch == "J":
    ch = "I"

  for row in range(5):
    for col in range(5):
      if matrix[row][col] == ch:
        return row, col

  return -1, -1

def prepare_text(input_text):
  text = ""
  for ch in input_text.upper():
    if ch.isalpha():
      if ch == "J":
        ch = "I"
      text += ch

  pairs = []
  i = 0
  while i < len(text):
    first = text[i]

    if i + 1 == len(text):
      second = "X"
      i += 1
    elif text[i] == text[i + 1]:
      second = "X"
      i += 1
    else:
      second = text[i + 1]
      i += 2

    pairs.append(first + second)

  return pairs

def playfair_encrypt(text, key):
  matrix = create_matrix(key)
  pairs = prepare_text(text)
  result = ""

  for pair in pairs:
    a = pair[0]
    b = pair[1]

    r1, c1 = find_position(matrix, a)
    r2, c2 = find_position(matrix, b)

    if r1 == r2:
      result += matrix[r1][(c1 + 1) % 5]
      result += matrix[r2][(c2 + 1) % 5]
    elif c1 == c2:
      result += matrix[(r1 + 1) % 5][c1]
      result += matrix[(r2 + 1) % 5][c2]
    else:
      result += matrix[r1][c2]
      result += matrix[r2][c1]

  return result

def playfair_decrypt(text, key):
  matrix = create_matrix(key)
  result = ""

  for i in range(0, len(text), 2):
    a = text[i]
    b = text[i + 1]

    r1, c1 = find_position(matrix, a)
    r2, c2 = find_position(matrix, b)

    if r1 == r2:
      result += matrix[r1][(c1 - 1) % 5]
      result += matrix[r2][(c2 - 1) % 5]
    elif c1 == c2:
      result += matrix[(r1 - 1) % 5][c1]
      result += matrix[(r2 - 1) % 5][c2]
    else:
      result += matrix[r1][c2]
      result += matrix[r2][c1]

  return result

def aes_encrypt(text):
  cipher = AES.new(AES_KEY, AES.MODE_CBC, IV)
  return cipher.encrypt(pad(text.encode(), AES.block_size))

def aes_decrypt(ciphertext):
  cipher = AES.new(AES_KEY, AES.MODE_CBC, IV)
  return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

def calculate_hash(ciphertext):
  return hashlib.sha256(ciphertext).hexdigest()


def sign_hash(hash_value):
  hash_int = int(hash_value, 16) % n
  return pow(hash_int, d, n)


def verify_signature(hash_value, signature):
  hash_int = int(hash_value, 16) % n
  verified_hash = pow(signature, e, n)
  return verified_hash == hash_int

# Doctor
def add_record():
    record_id = input("Enter Patient Record ID: ")
    name = input("Enter Patient Name: ")
    age = input("Enter Age: ")
    diagnosis = input("Enter Diagnosis: ")

    plaintext = "NAME:" + name + ";AGE:" + age + ";DIAGNOSIS:" + diagnosis

    playfair_cipher = playfair_encrypt(plaintext, PLAYFAIR_KEY)

    aes_cipher = aes_encrypt(playfair_cipher)

    hash_value = calculate_hash(aes_cipher)

    signature = sign_hash(hash_value)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    record = {
        "ID": record_id,
        "Name": name,
        "AES Cipher": aes_cipher,
        "Hash": hash_value,
        "Signature": signature,
        "Timestamp": timestamp,
        "Revoked": False
    }

    records.append(record)

    print("Record stored successfully.")
    print("Record ID:", record_id)
    print("Playfair Cipher:", playfair_cipher)
    print("AES Cipher:", aes_cipher.hex())
    print("SHA-256:", hash_value)
    print("Signature:", signature)
    print("Timestamp:", timestamp)
    
def doctor_view():
    for record in records:
        print("\nID:", record["ID"])
        print("Name:", record["Name"])
        print("AES Cipher:", record["AES Cipher"].hex())
        print("Hash:", record["Hash"])
        print("Signature:", record["Signature"])
        print("Timestamp:", record["Timestamp"])
        print("Revoked:", record["Revoked"])

def doctor_decrypt():
    record_id = input("Enter Record ID: ")

    for record in records:
        if record["ID"] == record_id:

            if record["Revoked"]:
                print("Record has been revoked.")
                return

            current_hash = calculate_hash(record["AES Cipher"])

            if current_hash != record["Hash"]:
                print("Integrity: INVALID")
                return

            print("Integrity: VALID")

            if not verify_signature(current_hash, record["Signature"]):
                print("Signature: INVALID")
                return

            print("Signature: VALID")

            playfair_cipher = aes_decrypt(record["AES Cipher"])
            plaintext = playfair_decrypt(playfair_cipher, PLAYFAIR_KEY)

            print("Playfair Cipher:", playfair_cipher)
            print("Patient Information:", plaintext)
            return

    print("Record not found.")


# Nurse
def nurse_view():
    for record in records:
        print("\nRecord ID:", record["ID"])
        print("AES Cipher:", record["AES Cipher"].hex())
        print("SHA-256:", record["Hash"])
        print("Signature:", record["Signature"])
        print("Timestamp:", record["Timestamp"])

def nurse_verify():
    record_id = input("Enter Record ID: ")

    for record in records:
        if record["ID"] == record_id:

            if record["Revoked"]:
                print("Record has been revoked.")
                return

            current_hash = calculate_hash(record["AES Cipher"])

            if current_hash != record["Hash"]:
                print("Integrity: INVALID")
                return

            print("Integrity: VALID")

            if verify_signature(current_hash, record["Signature"]):
                print("Authenticity: VALID")
            else:
                print("Authenticity: INVALID")
                return

            # Nurse can remove AES layer but cant Playfair decrypt
            playfair_cipher = aes_decrypt(record["AES Cipher"])

            print("AES Decryption Successful.")
            print("Playfair Ciphertext:", playfair_cipher)
            print("Plaintext Access: DENIED")
            return

    print("Record not found.") 
    
# Admin
def admin_view():
    for record in records:
        print("\nRecord ID:", record["ID"])
        print("Patient Name:", record["Name"])
        print("SHA-256:", record["Hash"])
        print("Timestamp:", record["Timestamp"])
        print("Revoked:", record["Revoked"])

def admin_verify():
    record_id = input("Enter Record ID: ")

    for record in records:
        if record["ID"] == record_id:
            if verify_signature(record["Hash"], record["Signature"]):
                print("Digital Signature: VALID")
            else:
                print("Digital Signature: INVALID")

            return

    print("Record not found.")
    
def admin_revoke():
    record_id = input("Enter Record ID: ")
    for record in records:
        if record["ID"] == record_id:
            record["Revoked"] = True
            print("Record revoked successfully.")
            return

    print("Record not found.")

# Tamper
def tamper_record():
    record_id = input("Enter Record ID: ")

    for record in records:
        if record["ID"] == record_id:
            data = bytearray(record["AES Cipher"])
            data[0] ^= 1
            record["AES Cipher"] = bytes(data)

            print("AES ciphertext modified.")
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
            print("1. Add Patient")
            print("2. View Records")
            print("3. Decrypt Patient")
            print("4. Tamper Test")
            print("5. Back")

            choice = int(input("Enter choice: "))

            if choice == 1:
                add_record()

            elif choice == 2:
                doctor_view()

            elif choice == 3:
                doctor_decrypt()

            elif choice == 4:
                tamper_record()

            elif choice == 5:
                break

            else:
                print("Invalid choice.")

    elif role == 2:
        while True:
            print("1. View Encrypted Records")
            print("2. Verify and Partially Decrypt")
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
            print("1. View Metadata")
            print("2. Verify Signature")
            print("3. Revoke Record")
            print("4. Back")

            choice = int(input("Enter choice: "))

            if choice == 1:
                admin_view()

            elif choice == 2:
                admin_verify()

            elif choice == 3:
                admin_revoke()

            elif choice == 4:
                break

            else:
                print("Invalid choice.")

    elif role == 4:
        print("Exiting...")
        break

    else:
        print("Invalid role.")