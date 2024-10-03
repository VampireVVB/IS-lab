from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
import binascii

# AES-256 Encryption and Decryption
aes_key = b"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"  # 32 bytes for AES-256
aes_message = "Encryption Strength"

# Function to encrypt using AES-256
def encrypt_aes(message, key):
    cipher = AES.new(key, AES.MODE_ECB)  # Using ECB mode for simplicity
    padded_message = pad(message.encode(), AES.block_size)  # Pad the message
    ciphertext = cipher.encrypt(padded_message)
    return ciphertext

# Function to decrypt using AES-256
def decrypt_aes(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)  # Using ECB mode for simplicity
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message

# Encrypt and decrypt using AES-256
aes_ciphertext = encrypt_aes(aes_message, aes_key)
aes_decrypted = decrypt_aes(aes_ciphertext, aes_key)

# Display AES results
print("AES-256 Ciphertext:", binascii.hexlify(aes_ciphertext).decode())
print("AES-256 Decrypted Message:", aes_decrypted.decode())

# DES Encryption and Decryption in CBC mode
des_key = b"A1B2C3D4"  # 8 bytes for DES
des_message = "Secure Communication"
iv = b"12345678"  # 8 bytes for DES IV

# Function to encrypt using DES in CBC mode
def encrypt_des_cbc(message, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)  # Using CBC mode
    padded_message = pad(message.encode(), DES.block_size)  # Pad the message
    ciphertext = cipher.encrypt(padded_message)
    return ciphertext

# Function to decrypt using DES in CBC mode
def decrypt_des_cbc(ciphertext, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)  # Using CBC mode
    decrypted_message = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return decrypted_message

# Encrypt and decrypt using DES
des_ciphertext = encrypt_des_cbc(des_message, des_key, iv)
des_decrypted = decrypt_des_cbc(des_ciphertext, des_key, iv)

# Display DES results
print("DES CBC Ciphertext:", binascii.hexlify(des_ciphertext).decode())
print("DES CBC Decrypted Message:", des_decrypted.decode())
