from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii

def aes_encrypt(plain_text, key):
    """Encrypts a message using AES-128."""
    # Use the first 16 bytes of the key for AES-128
    key = key[:16].encode()  
    # Create an AES cipher object in CBC mode
    cipher = AES.new(key, AES.MODE_CBC)
    # Pad the plaintext to be a multiple of 16 bytes
    padded_text = pad(plain_text.encode(), AES.block_size)
    # Encrypt the padded plaintext
    cipher_text = cipher.encrypt(padded_text)
    # Return the IV and ciphertext for decryption
    return cipher.iv, cipher_text

def aes_decrypt(iv, cipher_text, key):
    """Decrypts a message using AES-128."""
    # Use the first 16 bytes of the key for AES-128
    key = key[:16].encode()  
    # Create an AES cipher object with the provided key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Decrypt the ciphertext
    padded_plain_text = cipher.decrypt(cipher_text)
    # Unpad the plaintext
    plain_text = unpad(padded_plain_text, AES.block_size)
    return plain_text.decode()

# Define the key and plaintext
key = "0123456789ABCDEF0123456789ABCDEF"  # Full key provided
plain_text = "Sensitive Information"

# Encrypt the message
iv, cipher_text = aes_encrypt(plain_text, key)
print("Ciphertext (in hex):", binascii.hexlify(cipher_text).decode())

# Decrypt the message
decrypted_text = aes_decrypt(iv, cipher_text, key)
print("Decrypted message:", decrypted_text)
