# AFFINE CIPHER

def find_inverse(a):
    for i in range(1, 26):
        if (a*i) % 26 == 1:
            return i
        
    return -1

def affine_encrypt(text, a, b):
    result = ""
    for ch in text.upper():
        if ch.isalpha():
            p = ord(ch) - ord('A')
            c = (a * p + b) % 26
            result += chr(c + ord('A'))
            
    return result 

def affine_decrypt(ciphertext, a, b):
    result = ""
    inverse = find_inverse(a)
    if inverse == -1:
        print("Invalid value of 'a'")
        return ""

    for ch in ciphertext.upper():
        if ch.isalpha():
            c = ord(ch) - ord('A')
            p = (inverse * (c - b)) % 26
            result += chr(p + ord('A'))

    return result

text = input("Enter plaintext: ")
a = int(input("Enter value of a: "))
b = int(input("Enter value of b: "))

ciphertext = affine_encrypt(text, a, b)

print("Ciphertext:", ciphertext)

plaintext = affine_decrypt(ciphertext, a, b)

print("Decrypted text:", plaintext)