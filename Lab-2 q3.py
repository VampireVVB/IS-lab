import time
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import binascii

def des_encrypt(plain_text, key):
    """Encrypts a message using DES."""
    des = DES.new(key, DES.MODE_CBC)
    padded_text = pad(plain_text.encode(), DES.block_size)
    cipher_text = des.encrypt(padded_text)
    return des.iv, cipher_text

def des_decrypt(iv, cipher_text, key):
    """Decrypts a message using DES."""
    des = DES.new(key, DES.MODE_CBC, iv)
    padded_plain_text = des.decrypt(cipher_text)
    return unpad(padded_plain_text, DES.block_size).decode()

def aes_encrypt(plain_text, key):
    """Encrypts a message using AES-256."""
    aes = AES.new(key, AES.MODE_CBC)
    padded_text = pad(plain_text.encode(), AES.block_size)
    cipher_text = aes.encrypt(padded_text)
    return aes.iv, cipher_text

def aes_decrypt(iv, cipher_text, key):
    """Decrypts a message using AES-256."""
    aes = AES.new(key, AES.MODE_CBC, iv)
    padded_plain_text = aes.decrypt(cipher_text)
    return unpad(padded_plain_text, AES.block_size).decode()

def measure_time(cipher_func, *args):
    """Measures the time taken for encryption or decryption."""
    start_time = time.time()
    result = cipher_func(*args)
    end_time = time.time()
    return result, end_time - start_time

# Define the key and plaintext
des_key = b'12345678'  # DES key must be 8 bytes
aes_key = b'0123456789ABCDEF0123456789ABCDEF'  # AES-256 key must be 32 bytes
plain_text = "Performance Testing of Encryption Algorithms"

# Measure DES encryption and decryption times
des_iv, des_cipher_text = measure_time(des_encrypt, plain_text, des_key)
des_decrypted_text, des_decrypt_time = measure_time(des_decrypt, des_iv, des_cipher_text, des_key)

# Measure AES encryption and decryption times
aes_iv, aes_cipher_text = measure_time(aes_encrypt, plain_text, aes_key)
aes_decrypted_text, aes_decrypt_time = measure_time(aes_decrypt, aes_iv, aes_cipher_text, aes_key)

# Output the results
print(f"DES Encryption Time: {des_decrypt_time:.6f} seconds")
print(f"DES Decrypted Text: {des_decrypted_text}")

print(f"AES-256 Encryption Time: {aes_decrypt_time:.6f} seconds")
print(f"AES-256 Decrypted Text: {aes_decrypted_text}")


