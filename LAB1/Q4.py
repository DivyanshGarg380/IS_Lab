# VIGENERE CIPHER

def vignere_encrypt(text, key):
    result = ""
    key = key.upper();
    key_idx = 0
    for ch in text.upper():
        if ch.isalpha():
            p = ord(ch) - ord('A')
            k = ord(key[key_idx % len(key)]) - ord('A')
            c = (p + k) % 26
            result += chr(c + ord('A'))
            key_idx += 1
            
    return result 


def vigenere_decrypt(ciphertext, key):
    result = ""
    key = key.upper()
    key_index = 0

    for ch in ciphertext.upper():
        if ch.isalpha():
            c = ord(ch) - ord('A')
            k = ord(key[key_index % len(key)]) - ord('A')
            p = (c - k) % 26
            result += chr(p + ord('A'))
            key_index += 1

    return result

text = input("Enter plaintext: ")
key = input("Enter key: ")

ciphertext = vignere_encrypt(text, key)

print("Ciphertext:", ciphertext)

plaintext = vigenere_decrypt(ciphertext, key)

print("Decrypted text:", plaintext)