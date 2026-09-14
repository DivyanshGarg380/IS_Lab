# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248

# HealthCare → Rabin + Centralized Key Management

from datetime import datetime 

key_database = {}
audit_logs = []

def log_operation(operation, hospital):
    entry = {
        "time": str(datetime.now()),
        "operation": operation,
        "hospital": hospital
    }

    audit_logs.append(entry)

def rabin_key_generation(p, q):

    # Rabin requires p and q to be 3 mod 4
    if p % 4 != 3 or q % 4 != 3:
        print("Error: p and q must be 3 mod 4.")
        return None

    n = p * q

    public_key = n
    private_key = (p, q)

    return public_key, private_key

def generate_key_for_hospital(name, p, q):

    result = rabin_key_generation(p, q)

    if result is None:
        return

    public_key, private_key = result

    key_database[name] = {
        "public_key": public_key,
        "private_key": private_key,
        "status": "ACTIVE",
        "created": datetime.now()
    }

    log_operation("KEY GENERATED", name)

    print("Key generated for", name)
    
def distribute_key(name):

    if name not in key_database:
        print("Hospital not found.")
        return

    if key_database[name]["status"] == "REVOKED":
        print("Key has been revoked.")
        return

    print("\nPublic Key :", key_database[name]["public_key"])
    print("Private Key:", key_database[name]["private_key"])

    log_operation("KEY DISTRIBUTED", name)

def revoke_key(name):

    if name in key_database:
        key_database[name]["status"] = "REVOKED"

        log_operation("KEY REVOKED", name)

        print("Key revoked for", name)
    else:
        print("Hospital not found.")
        

def renew_key(name, p, q):

    if name in key_database:
        result = rabin_key_generation(p, q)

        if result:
            public_key, private_key = result

            key_database[name]["public_key"] = public_key
            key_database[name]["private_key"] = private_key
            key_database[name]["status"] = "ACTIVE"
            key_database[name]["created"] = datetime.now()

            log_operation("KEY RENEWED", name)

            print("Key renewed for", name)
            
def show_logs():

    print("\nAUDIT LOG")

    for log in audit_logs:
        print(log)
        
        
# Main program
print("HealthCare Rabin Key Management")

p = int(input("Enter Rabin prime p: "))
q = int(input("Enter Rabin prime q: "))

hospital = input("Enter hospital/clinic name: ")

generate_key_for_hospital(hospital, p, q)

# Distribution
distribute_key(hospital)

# Revocation
choice = input("\nDo you want to revoke the key? (yes/no): ")

if choice.lower() == "yes":
    revoke_key(hospital)

# Show audit logs
show_logs()