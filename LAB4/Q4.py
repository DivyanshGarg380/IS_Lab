# XYZ Logistics → Weak RSA attack + mitigation

from math import gcd

def factor_n(n):

    for p in range(2, int(n ** 0.5) + 1):

        if n % p == 0:
            q = n // p
            return p, q

    return None, None


def mod_inverse(e, phi):
    d = 1
    while (d * e) % phi != 1:
        d += 1

    return d


print("Vulnerable RSA Attack")

n = int(input("Enter RSA modulus n: "))
e = int(input("Enter public exponent e: "))

# Eve tries to factor n
p, q = factor_n(n)

if p is None or q is None:
    print("Could not factor n.")
else:
    print("\nRSA modulus successfully factored!")
    print("Recovered p =", p)
    print("Recovered q =", q)

    phi = (p - 1) * (q - 1)

    # Recover private exponent
    if gcd(e, phi) != 1:
        print("Invalid RSA public exponent.")
    else:
        d = mod_inverse(e, phi)
        print("phi(n) =", phi)
        print("Recovered private exponent d =", d)

        print("\nEve has recovered the RSA private key:")
        print("(n, d) =", (n, d))

print("\nMitigation")

print("1. Use sufficiently large RSA primes.")
print("2. Generate primes using a cryptographically secure random generator.")
print("3. Never use predictable or reused primes.")
print("4. Use secure RSA key-generation libraries.")
print("5. Rotate compromised RSA keys immediately.")