# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248

# AUTOKEY CIPHER

def autokey_encrypt(input_text, key):
    result = ""
    text = ""
    for ch in input_text.upper():
        if ch.isalpha():
            text += ch
            
    key_stream = [key]
    for i in range(len(text)):
        p = ord(text[i]) - ord('A')
        k = key_stream[i]
        c= (p + k) % 26
        result += chr(c + ord('A'))
        key_stream.append(p)
        
    return result 

def autokey_decrypt(ciphertext, key):
    result = ""
    key_stream = [key]

    for i in range(len(ciphertext)):
        c = ord(ciphertext[i]) - ord('A')
        k = key_stream[i]
        p = (c - k) % 26
        result += chr(p + ord('A'))
        # IMPORTANT:
        # During decryption we append recovered plaintext
        key_stream.append(p)

    return result

input_text = input("Enter plaintext: ")
key = int(input("Enter initial key: "))

ciphertext = autokey_encrypt(input_text, key)

print("Ciphertext:", ciphertext)

plaintext = autokey_decrypt(ciphertext, key)

print("Decrypted text:", plaintext)