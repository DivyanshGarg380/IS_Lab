# SecureCorp → RSA + Diffie-Hellman + Key Management

from math import gcd

def rsa_key_generation(p, q, e):
    n = p * q
    phi = (p - 1) * (q - 1)
    
    if gcd(e, phi) != 1:
        print("Invalid")
        exit()
        
    d = 1
    while (d * e) % phi != 1:
        d += 1
        
    return (n, e), (n, d)

def rsa_encrypt(message, public_key):
    n, e = public_key

    ciphertext = []

    for ch in message:
        m = ord(ch)

        if m >= n:
            print("Message character is too large for this RSA key.")
            return []

        c = pow(m, e, n)
        ciphertext.append(c)

    return ciphertext


def rsa_decrypt(ciphertext, private_key):
    n, d = private_key

    message = ""

    for c in ciphertext:
        m = pow(c, d, n)
        message += chr(m)

    return message

def diffie_hellman(p, g, a, b):

    # Alice's public key
    A = pow(g, a, p)

    # Bob's public key
    B = pow(g, b, p)

    # Both calculate the same shared secret
    secret_A = pow(B, a, p)
    secret_B = pow(A, b, p)

    return A, B, secret_A, secret_B


# Key Management

key_manager = {}

def add_system(name, public_key, private_key):
    key_manager[name] = {
        "public_key": public_key,
        "private_key": private_key,
        "status": "ACTIVE"
    }


def revoke_key(name):
    if name in key_manager:
        key_manager[name]["status"] = "REVOKED"
        print("Key revoked for", name)
    else:
        print("System not found.")


def show_systems():
    print("\n--- Key Management System ---")

    for name, data in key_manager.items():
        print(name, ":", data["status"])
        
# Main program

print("SecureCorp Secure Communication System")

# RSA keys
p = int(input("Enter RSA prime p: "))
q = int(input("Enter RSA prime q: "))
e = int(input("Enter RSA public exponent e: "))

result = rsa_key_generation(p, q, e)

if result:
    public_key, private_key = result

    print("Public Key :", public_key)
    print("Private Key:", private_key)

    add_system("Finance System", public_key, private_key)

    message = input("Enter document/message: ")

    encrypted = rsa_encrypt(message, public_key)

    print("Encrypted:", encrypted)

    decrypted = rsa_decrypt(encrypted, private_key)

    print("Decrypted:", decrypted)


# Diffie-Hellman
print("\nDiffie-Hellman Key Exchange")

p = int(input("Enter DH prime p: "))
g = int(input("Enter DH generator g: "))
a = int(input("Enter Alice private key: "))
b = int(input("Enter Bob private key: "))

A, B, secret_A, secret_B = diffie_hellman(p, g, a, b)

print("Alice public key:", A)
print("Bob public key:", B)
print("Alice shared secret:", secret_A)
print("Bob shared secret:", secret_B)

if secret_A == secret_B:
    print("Secure shared key established!")


# Add other systems
add_system("HR System", public_key, private_key)
add_system("Supply Chain System", public_key, private_key)

show_systems()

# Revoke one key
system = input("\nEnter system to revoke: ")
revoke_key(system)

show_systems()