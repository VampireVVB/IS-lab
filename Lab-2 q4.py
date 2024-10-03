from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import binascii

def triple_des_encrypt(plain_text, key):
    """Encrypts a message using Triple DES."""
    # Use only the first 24 bytes of the key for 3DES
    key = key[:24].encode()  
    # Create a Triple DES cipher object in CBC mode
    cipher = DES3.new(key, DES3.MODE_CBC)
    # Pad the plaintext to be a multiple of 8 bytes
    padded_text = pad(plain_text.encode(), DES3.block_size)
    # Encrypt the padded plaintext
    cipher_text = cipher.encrypt(padded_text)
    return cipher.iv, cipher_text

def triple_des_decrypt(iv, cipher_text, key):
    """Decrypts a message using Triple DES."""
    # Use only the first 24 bytes of the key for 3DES
    key = key[:24].encode()  
    # Create a Triple DES cipher object with the provided key and IV
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    # Decrypt the ciphertext
    padded_plain_text = cipher.decrypt(cipher_text)
    # Unpad the plaintext
    plain_text = unpad(padded_plain_text, DES3.block_size)
    return plain_text.decode()

# Define the key and plaintext
key = "1234567890ABCDEF1234567890ABCDEF"  # Key must be 24 bytes for Triple DES
plain_text = "Classified Text"

# Encrypt the message
iv, cipher_text = triple_des_encrypt(plain_text, key)
print("Ciphertext (in hex):", binascii.hexlify(cipher_text).decode())

# Decrypt the message
decrypted_text = triple_des_decrypt(iv, cipher_text, key)
print("Decrypted message:", decrypted_text)
