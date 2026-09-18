# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248

# PLAYFAIR CIPHER

def create_matrix(key):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    used = ""
    for ch in key.upper():
        if ch == 'J':
            ch = 'I'
            
        if ch.isalpha() and ch not in used:
            used += ch
            
    # Append the rest of the alphabet
    for ch in alphabet:
        if ch not in used:
            used += ch
            
    matrix = []
    for i in range(0, 25, 5):
        matrix.append(list(used[i:i+5]))
        
        
    return matrix 

def find_position(matrix, ch):
    if ch == 'J':
        ch = 'I'
        
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == ch:
                return row, col 
            
    return -1, -1

def prepare_text(input_text):
    text = ""
    for ch in input_text.upper():
        if ch.isalpha():
            if ch == 'J':
                ch = 'I'
                
            text += ch 
            
    pairs = []
    i = 0
    while i < len(text):
        first = text[i]
        
        # last character
        if i + 1 == len(text):
            second = 'X'
            i += 1
            
        # repeated characters
        elif text[i] == text[i+1]:
            second = 'X'
            i += 1
            
        else:
            second = text[i+1]
            i += 2
            
        pairs.append(first + second)
        
    return pairs

def playfair_encrypt(text, key):
    matrix = create_matrix(key)
    pairs = prepare_text(text)
    result = ""
    
    for pair in pairs:
        a = pair[0]
        b = pair[1]
        
        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)
        
        # Same row
        if r1 == r2:
            result += matrix[r1][(c1 + 1) % 5]
            result += matrix[r2][(c2 + 1) % 5]
            
        # Same column
        if c1 == c2:
            result += matrix[(r1 + 1) % 5][c1]
            result += matrix[(r2 + 1) % 5][c2]
            
        # Rectange rule
        else:
            result += matrix[r1][c2]
            result += matrix[r2][c1]
            
    return result 

def playfair_decrypt(text, key):
    matrix = create_matrix(key)
    result = ""

    for i in range(0, len(text), 2):
        a = text[i]
        b = text[i + 1]

        r1, c1 = find_position(matrix, a)
        r2, c2 = find_position(matrix, b)

        if r1 == r2:
            result += matrix[r1][(c1 - 1) % 5]
            result += matrix[r2][(c2 - 1) % 5]

        elif c1 == c2:
            result += matrix[(r1 - 1) % 5][c1]
            result += matrix[(r2 - 1) % 5][c2]

        else:
            result += matrix[r1][c2]
            result += matrix[r2][c1]

    return result

    
input_text = input("Enter plaintext: ")
key = input("Enter key: ")

matrix = create_matrix(key)

print("\nPlayfair Matrix:")

for row in matrix:
    print(row)

ciphertext = playfair_encrypt(input_text, key)

print("\nCiphertext:", ciphertext)