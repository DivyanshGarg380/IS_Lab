# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    A company has a control station that sends firmware commands to remote devices.

    Implement a menu-driven Python program with the following features:

    1. Device setup
        - Use Diffie–Hellman with p=23, g=5, station private exponent a=6, and device private exponent b=15.
        - Both sides calculate the shared secret independently.
        - Derive an AES-128 key from the shared secret using SHA-256.
    2. Send command
        - Accept a command ID, device ID, and command text.
        - Encrypt the command using AES-CBC.
        - Calculate an HMAC-SHA256 over the command ID, device ID, IV, and ciphertext.
        - Maintain a list of processed command IDs to prevent replay.
    3. Device receives command
        - Verify the HMAC before decryption.
        - Reject duplicate command IDs.
        - Decrypt the command only if authentication passes.
    4. Maintenance officer
        - Demonstrate DES encryption of a diagnostic message.
        - Display ciphertext in hexadecimal and recover the original message.
'''

from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
import hashlib
import hmac

p = 23
g = 5
a = 6
b = 15

station_public = pow(g, a, p)
device_public = pow(g, b, p)

station_secret = pow(device_public, a, p)
device_secret = pow(station_public, b, p)

print("Station public:", station_public)
print("Device public:", device_public)
print("DH verified:", station_secret == device_secret)

aes_key = hashlib.sha256(str(station_secret).encode()).digest()[:16]
auth_key = hashlib.sha256(b"auth|" + str(station_secret).encode()).digest()

des_key = b"8bytekey"

processed_ids = []
pending_commands = []

while True:
    print("\n1. Send command")
    print("2. Device receives command")
    print("3. DES diagnostic")
    print("4. Exit")

    choice = input("Choose: ")

    if choice == "1":
        command_id = input("Command ID: ")
        device_id = input("Device ID: ")
        command = input("Command text: ")
        
        duplicate = False
        for item in pending_commands:
            if item["id"] == command_id:
                duplicate = True
                break
            
        if command_id in processed_ids or duplicate:
            print("Duplicate command ID")
            continue
        
        iv = b"1234567890123456"

        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(command.encode(), AES.block_size))

        message = command_id.encode() + b"|" + device_id.encode() + b"|" + iv + ciphertext

        tag = hmac.new(auth_key, message, hashlib.sha256).hexdigest()
        
        pending_commands.append({
            "id": command_id,
            "device": device_id,
            "iv": iv,
            "ciphertext": ciphertext,
            "tag": tag
        })
        
        print("Ciphertext hex:", ciphertext.hex())
        print("HMAC:", tag)
        print("Command queued")
        
    elif choice == "2":
        command_id = input("Command ID to receive: ")
        found = False

        for item in pending_commands:
            if item["id"] == command_id:
                found = True

                message = item["id"].encode() + b"|" + item["device"].encode() + b"|" + item["iv"] + item["ciphertext"]

                expected_tag = hmac.new(auth_key, message, hashlib.sha256).hexdigest()

                if not hmac.compare_digest(expected_tag, item["tag"]):
                    print("Authentication failed")
                    break

                if item["id"] in processed_ids:
                    print("Replay detected")
                    break

                cipher = AES.new(aes_key, AES.MODE_CBC, item["iv"])

                plaintext = unpad(cipher.decrypt(item["ciphertext"]), AES.block_size).decode()

                processed_ids.append(item["id"])
                print("Authenticated command:", plaintext)

                break

        if not found:
            print("Command not found")

    elif choice == "3":
        message = input("Diagnostic message: ").encode()

        cipher = DES.new(des_key, DES.MODE_ECB)
        encrypted = cipher.encrypt(pad(message, DES.block_size))

        print("DES ciphertext hex:", encrypted.hex())

        cipher = DES.new(des_key, DES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(encrypted), DES.block_size)

        print("Recovered:", decrypted.decode())

    elif choice == "4":
        break

    else:
        print("Invalid choice")
