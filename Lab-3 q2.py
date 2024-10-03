from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Generate ECC private and public key pair
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

# Define the message
message = b"Secure Transactions"

# Function to encrypt the message using ECC
def encrypt_ecc(message, public_key):
    ciphertext = public_key.encrypt(
        message,
        ec.ECIES(algorithm=hashes.SHA256(), label=None)
    )
    return ciphertext

# Function to decrypt the ciphertext using ECC
def decrypt_ecc(ciphertext, private_key):
    decrypted_message = private_key.decrypt(
        ciphertext,
        ec.ECIES(algorithm=hashes.SHA256(), label=None)
    )
    return decrypted_message

# Encrypt the message
ciphertext = encrypt_ecc(message, public_key)

# Decrypt the ciphertext
decrypted_message = decrypt_ecc(ciphertext, private_key)

# Display results
print("ECC Ciphertext:", ciphertext.hex())
print("ECC Decrypted Message:", decrypted_message.decode())
