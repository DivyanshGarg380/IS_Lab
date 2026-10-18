# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
Implement RSA encryption and decryption for two integers, 7 and 3, using p=11, q=13, e=7. 
Multiply their ciphertexts without decrypting them, then decrypt the result and verify that it equals the product of the original integers.
'''

import math
p = 11
q = 13
n = p * q
phi = (p - 1) * (q - 1)

e = 7
d = pow(e, -1, phi)

def encrypt(mess):
    return pow(mess, e, n)

def decrypt(mess):
    return pow(mess, d, n)

m1, m2 = 7, 3
c1 = encrypt(m1)
c2 = encrypt(m2)

prod = (c1 * c2) % n
result = decrypt(prod)

if result == m1 * m2:
    print("Homomorphic multiplication verified!")
else:
    print("Verification failed!")