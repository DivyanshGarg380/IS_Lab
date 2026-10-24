# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    Develop a Python program called NurseryLink that calculates the total plants in a rectangular arrangement while keeping rows and plants_per_row encrypted at an external service.

    Given:
    - p=31, g=3, x=4, r_1=3, r_2=5
    - Main inputs: rows = 4, plants_per_row = 5
    - Each input must be an integer from 1 to 30.
    - Use manual Diffie–Hellman and ElGamal arithmetic. Python pow() and modular inverse are allowed.
    - No cryptographic libraries or sockets required. File handling is optional.
    Requirements:
    1. Calculate public values Y=g^xmod p, A_1=g^{r_1}mod p, and A_2=g^{r_2}mod p.
    2. Calculate and verify both Diffie–Hellman shared secrets independently at the sender and receiver.
    3. Encrypt both inputs using ElGamal and verify that the receiver can recover them.
    4. The service must multiply ciphertext components to produce an encrypted product without accessing plaintexts or secrets.
    5. The receiver must decrypt only the total ciphertext and verify the result against the sender’s ordinary product.
    6. Demonstrate:
    - 4 × 5 = 20
    - 7 × 6 = 42, giving modular result 11
    - Reject rows = 31 before encryption.
    7. Display all required public values, secrets, ciphertexts, recovered inputs, and verification results. Use separate functions for the required operations.
'''

p = 31
g = 3
x = 4
r1 = 3
r2 = 5

def public_value(g, exponent, p):
    return pow(g, exponent, p)

def shared_secret(public, exponent, p):
    return pow(public, exponent, p)

def validate(value):
    try:
        value = int(value)
        if 1 <= value <= 30:
            return value
    except ValueError:
        pass

    return None

def encrypt(value, A, K, p):
    B = (value * K) % p
    return (A, B)

def decrypt(cipher, K, p):
    A, B = cipher
    inverse = pow(K, -1, p)
    return (B * inverse) % p

def service(C1, C2, p):
    A1, B1 = C1
    A2, B2 = C2

    A_total = (A1 * A2) % p
    B_total = (B1 * B2) % p

    return (A_total, B_total)

def run_nursery(row_input, plants_input):
    rows = validate(row_input)
    plants = validate(plants_input)
    
    if rows is None or plants is None:
        print("Invalid input: enter integers from 1 to 30.")
        return

    Y = public_value(g, x, p)
    A1 = public_value(g, r1, p)
    A2 = public_value(g, r2, p)
    
    K1 = shared_secret(Y, r1, p)
    K2 = shared_secret(Y, r2, p)
    
    K1_receiver = shared_secret(A1, x, p)
    K2_receiver = shared_secret(A2, x, p)
    
    print("\nY =", Y, "A1 =", A1, "A2 =", A2)
    print("Sender secrets:", K1, K2)
    print("Receiver secrets:", K1_receiver, K2_receiver)

    if K1 != K1_receiver or K2 != K2_receiver:
        print("DH Check Failed")
        return

    print("DH Check Passed")
    
    C1 = encrypt(rows, A1, K1, p)
    C2 = encrypt(plants, A2, K2, p)
    
    recovered_rows = decrypt(C1, K1_receiver, p)
    recovered_plants = decrypt(C2, K2_receiver, p)
    
    print("C1 =", C1)
    print("C2 =", C2)
    print("Recovered rows =", recovered_rows)
    print("Recovered plants_per_row =", recovered_plants)

    if recovered_rows != rows or recovered_plants != plants:
        print("Encryption Check Failed")
        return

    print("Encryption Check Passed")
    
    C_total = service(C1, C2, p)
    print("C_total =", C_total)
    
    A_total, B_total = C_total
    K_total = shared_secret(A_total, x, p)
    result = (B_total * pow(K_total, -1, p)) % p

    ordinary_product = rows * plants
    expected = ordinary_product % p

    print("K_total =", K_total)
    print("Encrypted result =", result)
    print("Ordinary product =", ordinary_product)
    print("Expected modulo p =", expected)

    if result == expected:
        print("Product Verified")
    else:
        print("Product Failed")


print("----- RUN 1 -----")
run_nursery(4, 5)

print("\n----- RUN 2 -----")
run_nursery(7, 6)

print("\n----- INVALID INPUT TEST -----")
run_nursery(31, 5)
