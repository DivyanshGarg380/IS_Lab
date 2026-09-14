# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248

# ADDITIVE CIPHER

def additive_encrypt(text, key):
    result = ""
    for ch in text.upper():
        if ch.isalpha():
            p = ord(ch) - ord('A')
            c = (p + key) % 26 
            result += chr(c + ord('A'))
            
    return result 

def additive_decrypt(cipher, key):
    result = ""
    for ch in cipher.upper():
        if ch.isalpha():
            c = ord(ch) - ord('A')
            p = (c - key) % 26
            result += chr(p + ord('A'))
            
    return result 

text = input("Enter plaintext: ")
key = input("Enter key: ")

ciphertext = additive_encrypt(text, key)
print("Ciphertext:", ciphertext)

plaintext = additive_decrypt(ciphertext, key)
print("Decrypted text:", plaintext)