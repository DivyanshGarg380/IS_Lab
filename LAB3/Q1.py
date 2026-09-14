# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248

# RSA Ecryption and Decyption

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    
    return a

def mod_inverse(e, phi):
    for d in range(1, phi):
        if (e * d) % phi == 1:
            return d
        
    return -1

p = int(input("Enter prime p"))
q = int(input("Enter prime q"))

n = p * q
phi = (p - 1) * (q - 1)

e = int(input("Enter public exponent e"))

if gcd(e, phi) != 1:
    print("Invalid e!")
    exit()
    
d = mod_inverse(e, phi)

print("\nPublic Key :", (n, e))
print("Private Key:", (n, d))

# Ecrypt
message = input("Enter message: ")
ciphertext = []

for ch in message:
    m = ord(ch)
    
    if m >= n:
        print("Msg character is to large for n")
        exit()
        
    # c = m ^ e mod n
    c = pow(m, e, n)
    ciphertext.append(c)
    
print("Ciphertext: ", ciphertext)

# Decrypt

decrypted = ""
for c in ciphertext:
    # m = c ^ d mod n
    m = pow(c, d, n)
    decrypted += chr(m)
    
print("Decrypted Msg: ", decrypted)
