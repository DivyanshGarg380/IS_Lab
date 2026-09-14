# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248

# HILL CIPHER

def hill_encrypt(input_text):
    text = ""
    for ch in input_text.upper():
        if ch.isalpha():
            text += ch
            
    if len(text) % 2 != 0:
        text += 'X'
        
    result = ""
    
    # key matrix example taken
    a, b, c, d = 3, 3, 2, 7
    
    for i in range(0, len(text), 2):
        x = ord(text[i]) - ord('A')
        y = ord(text[i+1]) - ord('A')
        
        # Matrix multiplication
        first = (a * x + b * y) % 26
        second = (c * x + d * y) % 26
        
        result += chr(first + ord('A'))
        result += chr(second + ord('A'))
        
    return result 

def hill_decrypt(ciphertext):
    result = ""

    # Inverse key matrix
    a = 23
    b = 5
    c = 12
    d = 21

    for i in range(0, len(ciphertext), 2):
        x = ord(ciphertext[i]) - ord('A')
        y = ord(ciphertext[i + 1]) - ord('A')

        first = (a * x + b * y) % 26
        second = (c * x + d * y) % 26

        result += chr(first + ord('A'))
        result += chr(second + ord('A'))

    return result


ciphertext = input("Enter ciphertext: ")

plaintext = hill_decrypt(ciphertext)

print("Decrypted text:", plaintext)

input_text = input("Enter plaintext: ")

ciphertext = hill_encrypt(input_text)

print("Ciphertext:", ciphertext)