import hashlib
import math

from Crypto.Util.number import getPrime, inverse, GCD

def generate_keypair(bits=512):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)

    while p == q:
        q = getPrime(bits // 2)

    n = p * q
    g = n + 1
    lam = math.lcm(p - 1, q - 1)

    n_squared = n * n
    x = pow(g, lam, n_squared)
    L = (x - 1) // n
    mu = inverse(L, n)

    return (n, g), (lam, mu)


def encrypt(public_key, message):
    n, g = public_key
    n_squared = n * n

    if not 0 <= message < n:
        raise ValueError("Message must be between 0 and n-1")

    while True:
        r = __import__("secrets").randbelow(n - 1) + 1
        if GCD(r, n) == 1:
            break

    return (
        pow(g, message, n_squared)
        * pow(r, n, n_squared)
    ) % n_squared

def encrypt_keyword(public_key, message):
    n, g = public_key
    return pow(g, message, n * n)

def decrypt(public_key, private_key, ciphertext):
    n, g = public_key
    lam, mu = private_key
    n_squared = n * n

    x = pow(ciphertext, lam, n_squared)
    L = (x - 1) // n

    return (L * mu) % n


def word_to_integer(word):
    digest = hashlib.sha256(word.lower().encode()).digest()
    return int.from_bytes(digest, "big")


def tokenize(text):
    import re
    return re.findall(r"\b[a-z0-9]+\b", text.lower())


def create_index(documents, public_key):
    index = {}
    n, g = public_key

    for doc_id, document in documents.items():
        for word in set(tokenize(document)):
            message = word_to_integer(word)

            message %= n

            encrypted_word = encrypt_keyword(public_key, message)

            if encrypted_word not in index:
                index[encrypted_word] = []

            numeric_id = int(doc_id.replace("doc", ""))
            encrypted_id = encrypt(public_key, numeric_id)

            index[encrypted_word].append(encrypted_id)

    return index


def search(encrypted_index, query, public_key, private_key):
    words = tokenize(query)

    if not words:
        return []

    query_integer = word_to_integer(words[0])
    query_integer %= public_key[0]

    encrypted_query = encrypt_keyword(public_key, query_integer)

    if encrypted_query not in encrypted_index:
        return []

    results = []

    for encrypted_id in encrypted_index[encrypted_query]:
        numeric_id = decrypt(public_key, private_key, encrypted_id)
        results.append(f"doc{numeric_id}")

    return results

documents = {
    "doc1": "Python supports secure encryption algorithms",
    "doc2": "AES provides symmetric data encryption",
    "doc3": "Public key cryptography uses two keys",
    "doc4": "Searchable encryption protects private documents",
    "doc5": "Network security detects malicious traffic",
    "doc6": "Python programming simplifies data analysis",
    "doc7": "AES encryption uses a secret key",
    "doc8": "Cryptography helps protect sensitive information",
    "doc9": "Secure databases store encrypted records",
    "doc10": "Search systems retrieve matching documents",
}

public_key, private_key = generate_keypair()

encrypted_index = create_index(documents, public_key)

print("Total documents:", len(documents))
print("Encrypted inverted index created.")

query = input("Enter a keyword to search: ").strip()

results = search(encrypted_index, query, public_key, private_key)

print("\nSearch results for:", query)

if results:
    for doc_id in results:
        print(doc_id, ":", documents[doc_id])
else:
    print("No matching documents found.")
