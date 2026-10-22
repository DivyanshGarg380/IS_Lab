# Author :

# ███████╗████████╗ █████╗ ██████╗  ███╗   ███╗ █████╗ ███╗   ██╗
# ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗ ████╗ ████║██╔══██╗████╗  ██║
# ███████╗   ██║   ███████║██████╔╝ ██╔████╔██║███████║██╔██╗ ██║
# ╚════██║   ██║   ██╔══██║██║  ██║ ██║╚██╔╝██║██╔══██║██║╚██╗██║
# ███████║   ██║   ██║  ██║██║  ██║ ██║ ╚═╝ ██║██║  ██║██║ ╚████║
# ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝  STARMAN248  

'''
    An industrial sensor sends readings to a server. 
    The client and server derive a shared AES key using Diffie–Hellman. 
    The client encrypts its message using AES-CBC and sends its SHA-256 hash. 
    The server decrypts the message and verifies its integrity before accepting it.

    Requirements:
    - Use TCP sockets.
    - Use Diffie–Hellman with \(p=23,\ g=5,\ a=6,\ b=15\).
    - Derive a 256-bit AES key from the shared secret.
    - Only Client can submit readings.
    - Only Admin can view the server's audit log.
    - Provide a menu-driven client.
    - No JSON or file operations.
'''

