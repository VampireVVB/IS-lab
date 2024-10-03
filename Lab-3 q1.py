from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

# Define the RSA key pair (for demonstration purposes)
# In a real-world scenario, these would be generated securely.
key = RSA.generate(2048)  # Generate a new RSA key pair
private_key = key.export_key()
public_key = key.publickey().export_key()

# Load the public and private keys
private_key = RSA.import_key(private_key)
public_key = RSA.import_key(public_key)

# Define the message
message = "Asymmetric Encryption"

# Function to encrypt using RSA
def encrypt_rsa(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message.encode())
    return ciphertext

# Function to decrypt using RSA
def decrypt_rsa(ciphertext, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(ciphertext)
    return decrypted_message

# Encrypt the message
ciphertext = encrypt_rsa(message, public_key)

# Decrypt the ciphertext
decrypted_message = decrypt_rsa(ciphertext, private_key)

# Display results
print("RSA Ciphertext:", binascii.hexlify(ciphertext).decode())
print("RSA Decrypted Message:", decrypted_message.decode())
