# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248

# MULTIPLICATIVE CIPHER

def find_inverse(key):
    for i in range(1, 26):
        if (key * i) % 26 == 1:
            return i
        
    return -1

def multiplicative_encrypt(text, key):
    result = ""

    for ch in text.upper():
        if ch.isalpha():
            p = ord(ch) - ord('A')
            c = (p * key) % 26
            result += chr(c + ord('A'))

    return result


def multiplicative_decrypt(ciphertext, key):
    result = ""
    inverse = find_inverse(key)

    if inverse == -1:
        print("Invalid key!")
        return ""

    for ch in ciphertext.upper():
        if ch.isalpha():
            c = ord(ch) - ord('A')
            p = (c * inverse) % 26
            result += chr(p + ord('A'))

    return result


text = input("Enter plaintext: ")
key = int(input("Enter key: "))

ciphertext = multiplicative_encrypt(text, key)
print("Ciphertext:", ciphertext)

plaintext = multiplicative_decrypt(ciphertext, key)
print("Decrypted text:", plaintext) 