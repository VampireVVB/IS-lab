from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import binascii

def des_encrypt(plain_text, key):
    """Encrypts a message using DES."""
    # Create a DES cipher object with the provided key
    des = DES.new(key, DES.MODE_CBC)
    # Pad the plaintext to be a multiple of 8 bytes
    padded_text = pad(plain_text.encode(), DES.block_size)
    # Encrypt the padded plaintext
    cipher_text = des.encrypt(padded_text)
    # Return the IV and ciphertext for decryption
    return des.iv, cipher_text

def des_decrypt(iv, cipher_text, key):
    """Decrypts a message using DES."""
    # Create a DES cipher object with the provided key and IV
    des = DES.new(key, DES.MODE_CBC, iv)
    # Decrypt the ciphertext
    padded_plain_text = des.decrypt(cipher_text)
    # Unpad the plaintext
    plain_text = unpad(padded_plain_text, DES.block_size)
    return plain_text.decode()

# Define the key and plaintext
key = b'A1B2C3D4'  # Key must be 8 bytes for DES
plain_text = "Confidential Data"

# Encrypt the message
iv, cipher_text = des_encrypt(plain_text, key)
print("Ciphertext (in hex):", binascii.hexlify(cipher_text).decode())

# Decrypt the message
decrypted_text = des_decrypt(iv, cipher_text, key)
print("Decrypted message:", decrypted_text)
