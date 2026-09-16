# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248

# HILL CIPHER

K = [[3, 3], [2, 5]]

def hill_encrypt(text):

    text = text.upper().replace(" ", "")

    while len(text) % 2 != 0:
        text += "X"

    result = ""

    for i in range(0, len(text), 2):

        x1 = ord(text[i]) - ord('A')
        x2 = ord(text[i + 1]) - ord('A')

        y1 = (K[0][0] * x1 + K[0][1] * x2) % 26
        y2 = (K[1][0] * x1 + K[1][1] * x2) % 26

        result += chr(y1 + ord('A'))
        result += chr(y2 + ord('A'))

    return result


def hill_decrypt(text):

    det = K[0][0] * K[1][1] - K[0][1] * K[1][0]
    det = det % 26

    det_inverse = pow(det, -1, 26)

    inverse_matrix = [
        [(K[1][1] * det_inverse) % 26, (-K[0][1] * det_inverse) % 26],
        [(-K[1][0] * det_inverse) % 26, (K[0][0] * det_inverse) % 26]
    ]

    result = ""

    for i in range(0, len(text), 2):

        x1 = ord(text[i]) - ord('A')
        x2 = ord(text[i + 1]) - ord('A')

        y1 = (inverse_matrix[0][0] * x1 + inverse_matrix[0][1] * x2) % 26
        y2 = (inverse_matrix[1][0] * x1 + inverse_matrix[1][1] * x2) % 26

        result += chr(y1 + ord('A'))
        result += chr(y2 + ord('A'))

    return result


input_text = input("Enter plaintext: ")

ciphertext = hill_encrypt(input_text)

print("Ciphertext:", ciphertext)