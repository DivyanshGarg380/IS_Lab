# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    A manufacturing plant encrypts numeric fault readings using textbook RSA. 
    The auditor must combine two ciphertexts using RSA's multiplicative homomorphic property, verify the hash of the combined ciphertext representation, and only then permit an engineer 
    to recover the product modulo n.

    Implement a menu-driven program with:
    - Engineer: encrypt two readings and combine their ciphertexts.
    - Auditor: verify the integrity hash.
    - Admin: simulate tampering.
    - The engineer may decrypt the combined result only after the auditor has verified it.
    Given parameters: p=61, q=53, e=17.
'''

import hashlib

p, q, e = 61, 53, 17
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

combined_cipher = None
stored_hash = ""
verified = False
expected_product = None

while True:
    print("\n1. Encrypt and Combine Readings")
    print("2. Verify Combined Ciphertext")
    print("3. Decrypt Combined Result")
    print("4. Tamper With Ciphertext")
    print("0. Exit")

    choice = input("Choice: ")
    role = input("Role (Engineer/Auditor/Admin): ")

    if choice == "1":
        if role != "Engineer":
            print("Access denied")
            continue

        m1 = int(input("First reading (0 to n-1): "))
        m2 = int(input("Second reading (0 to n-1): "))

        c1 = pow(m1, e, n)
        c2 = pow(m2, e, n)

        combined_cipher = (c1 * c2) % n
        expected_product = (m1 * m2) % n

        payload = str(combined_cipher).encode()
        payload_hex = payload.hex()

        recovered_bytes = bytes.fromhex(payload_hex)
        stored_hash = hashlib.sha256(recovered_bytes).hexdigest()

        verified = False

        print("Ciphertext 1:", c1)
        print("Ciphertext 2:", c2)
        print("Combined ciphertext:", combined_cipher)
        print("Payload hex:", payload_hex)
        print("SHA-256:", stored_hash)

    elif choice == "2":
        if role != "Auditor":
            print("Access denied")
            continue

        payload = str(combined_cipher).encode()
        current_hash = hashlib.sha256(payload).hexdigest()

        verified = current_hash == stored_hash
        print("Integrity valid:", verified)

    elif choice == "3":
        if role != "Engineer":
            print("Access denied")
            continue

        if combined_cipher is None:
            print("No ciphertext available")
            continue

        if not verified:
            print("Auditor verification required first")
            continue

        result = pow(combined_cipher, d, n)

        print("Decrypted product modulo n:", result)
        print("Expected product modulo n:", expected_product)
        print("Result correct:", result == expected_product)

    elif choice == "4":
        if role != "Admin":
            print("Access denied")
            continue

        if combined_cipher is None:
            print("No ciphertext available")
            continue

        combined_cipher = (combined_cipher + 1) % n
        verified = False

        print("Ciphertext modified.")
        print("Run integrity verification again.")

    elif choice == "0":
        break

    else:
        print("Invalid choice")
