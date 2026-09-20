# MD5 vs SHA-1 vs SHA-256

import hashlib
import random
import string
import time

def generate_strings(count):
    data = []

    for i in range(count):
        length = random.randint(10, 20)
        text = ''.join(
            random.choice(string.ascii_letters + string.digits)
            for _ in range(length)
        )
        data.append(text)

    return data

def test_algorithm(name, hash_function, data):
    hashes = []
    start_time = time.time()

    for text in data:
        text_bytes = text.encode()
        hash_value = hash_function(text_bytes).hexdigest()
        hashes.append(hash_value)

    end_time = time.time()
    execution_time = end_time - start_time
    unique_hashes = set(hashes)
    collisions = len(hashes) - len(unique_hashes)

    print("\nAlgorithm:", name)
    print("Execution Time:", execution_time, "seconds")
    print("Collisions:", collisions)


n = int(input("Enter number of random strings (50-100): "))
if n < 50 or n > 100:
    print("Please enter a number between 50 and 100.")

else:

    data = generate_strings(n)

    print("\nGenerated", n, "random strings.")

    # Test MD5
    test_algorithm("MD5", hashlib.md5, data)

    # Test SHA-1
    test_algorithm("SHA-1", hashlib.sha1, data)

    # Test SHA-256
    test_algorithm("SHA-256", hashlib.sha256, data)