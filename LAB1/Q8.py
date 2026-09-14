# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248

# KNOWN-PLAINTEXT ATTACK

plaintext = "YES"
ciphertext = "CIW"

# Find shift using first character
p = ord(plaintext[0]) - ord('A')
c = ord(ciphertext[0]) - ord('A')

key = (c - p) % 26

print("Detected key:", key)

target = "XVIEWYWI"

result = ""

for ch in target:
    x = ord(ch) - ord('A')
    p = (x - key) % 26
    result += chr(p + ord('A'))

print("Plaintext:", result)