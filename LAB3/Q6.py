# ECC Encryption and Decryption

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Generate ECC private and public keys

private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# Encrypt
message = b"Secure Transactions"

# Generate an ephemeral ECC key pair
ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
ephemeral_public_key = ephemeral_private_key.public_key()

shared_key = ephemeral_private_key.exchange(ec.ECDH(), public_key)

aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ECC encryption").derive(shared_key)

# Encrypt the message with AES-GCM
nonce = os.urandom(12)
aesgcm = AESGCM(aes_key)
ciphertext = aesgcm.encrypt(nonce, message, None)

print("Original Message:", message.decode())
print("Ciphertext:", ciphertext.hex())

# Decrypt 

shared_key_decryption = private_key.exchange(ec.ECDH(), ephemeral_public_key)

aes_key_decryption = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ECC encryption").derive(shared_key_decryption)

aesgcm_decryption = AESGCM(aes_key_decryption)
decrypted_message = aesgcm_decryption.decrypt(nonce, ciphertext, None)

print("Decrypted Message:", decrypted_message.decode())

# Verify

if decrypted_message == message:
    print("Verification: SUCCESS")
else:
    print("Verification: FAILED")
