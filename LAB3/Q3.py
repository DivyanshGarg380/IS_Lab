# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248

# Diffie-Hellman Key Exchange

p = int(input("Enter prime p: "))
g = int(input("Enter generator g: "))

# Private keys
a = int(input("Enter Alice's private key: "))
b = int(input("Enter Bob's private key: "))

# Generate public keys
A = pow(g, a, p)
B = pow(g, b, p)

print("Alice's Public Key:", A)
print("Bob's Public Key:", B)

# Calculate shared secrets
alice_secret = pow(B, a, p)
bob_secret = pow(A, b, p)

print("Alice's Shared Secret:", alice_secret)
print("Bob's Shared Secret:", bob_secret)

if alice_secret == bob_secret:
    print("Key Exchange Successful!")
else:
    print("Key Exchange Failed!")
    
