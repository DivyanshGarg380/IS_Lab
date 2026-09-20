# ELGAMAL Ecryption and Decyption

def mod_inverse(a, p):
    for i in range(1, p):
        if (a * i) % p == 1:
            return i

    return -1

# public parameters
p = int(input("Enter prime p: "))
g = int(input("Enter generator g: "))

# private key
x = int(input("Enter private key x: "))

y = pow(g, x, p)

print("\nPublic Key:", (p, g, y))
print("Private Key:", x)

# Encrypt
message = input("Enter message: ")

# Random key
k = int(input("Enter random key k: "))

# c1 = g ^ k mod p
c1 = pow(g, k, p)

# s = y ^ k mod p
s = pow(y, k, p)

ciphertext = []
for ch in message:
    m = ord(ch)
    if m >= p:
        print("Message character is too large for p.")
        exit()
        
    # c2 = m * s mod p
    c2 = (m * s) % p
    ciphertext.append((c1, c2))
        
print("Ciphertext: ", ciphertext)

decrypted = ""

for c1, c2 in ciphertext:
    # s = c1^x mod p
    s = pow(c1, x, p)

    # Find inverse of s
    s_inverse = mod_inverse(s, p)

    # m = c2 * s_inverse mod p
    m = (c2 * s_inverse) % p

    decrypted += chr(m)

print("Decrypted message:", decrypted)