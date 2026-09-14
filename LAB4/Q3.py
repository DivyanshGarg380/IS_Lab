# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248

# DigiRights → ElGamal + Key Management + Access Control

from datetime import datetime, timedelta

master_key = {}
content_database = {}
access_control = {}
logs = []

def log(operation):
    logs.append({
        "time": str(datetime.now()),
        "operation": operation
    })
    
def generate_elgamal_keys(p, g, x):
    y = pow(g, x, p)
    public_key = (p, g, y)
    private_key = x
    return public_key, private_key

def encrypt_content(message, public_key, k):
    p, g, y = public_key
    c1 = pow(g, k, p)
    shared_secret = pow(y, k, p)
    ciphertext = []
    for ch in message:
        m = ord(ch)
        c2 = (m * shared_secret) % p
        ciphertext.append(c2)

    return c1, ciphertext

def grant_access(customer, content, days):
    expiry = datetime.now() + timedelta(days=days)
    access_control[(customer, content)] = {
        "status": "ACTIVE",
        "expiry": expiry
    }
    log("ACCESS GRANTED to " + customer)
    
def check_access(customer, content):
    key = (customer, content)
    if key not in access_control:
        return False
    data = access_control[key]
    if data["status"] == "REVOKED":
        return False
    if datetime.now() > data["expiry"]:
        return False
    return True

def revoke_access(customer, content):
    key = (customer, content)
    if key in access_control:
        access_control[key]["status"] = "REVOKED"
        log("ACCESS REVOKED from " + customer)
        
# Main program

print("DigiRights DRM System")

p = int(input("Enter ElGamal prime p: "))
g = int(input("Enter generator g: "))
x = int(input("Enter private key x: "))

public_key, private_key = generate_elgamal_keys(p, g, x)

master_key["public"] = public_key
master_key["private"] = private_key

print("Public Key:", public_key)

content = input("Enter digital content: ")
k = int(input("Enter random encryption key k: "))

c1, ciphertext = encrypt_content(content, public_key, k)

content_id = input("Enter content ID: ")

content_database[content_id] = {
    "ciphertext": (c1, ciphertext),
    "creator": "ContentCreator"
}

log("CONTENT ENCRYPTED")

# Give customer access
customer = input("Enter customer name: ")
days = int(input("Access duration in days: "))

grant_access(customer, content_id, days)

if check_access(customer, content_id):
    print("Customer has access to content.")
else:
    print("Access denied.")


# Optional revocation
choice = input("Revoke access? (yes/no): ")

if choice.lower() == "yes":
    revoke_access(customer, content_id)

if check_access(customer, content_id):
    print("Access granted.")
else:
    print("Access denied.")


print("\nAUDIT LOG")

for entry in logs:
    print(entry)