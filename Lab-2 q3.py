import time
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import binascii

def des_encrypt(plain_text, key):
    """Encrypt a message using DES."""
    des = DES.new(key, DES.MODE_CBC)
    padded_text = pad(plain_text.encode(), DES.block_size)
    cipher_text = des.encrypt(padded_text)
    return des.iv, cipher_text

def des_decrypt(iv, cipher_text, key):
    """Decrypt a message using DES."""
    des = DES.new(key, DES.MODE_CBC, iv)
    padded_plain_text = des.decrypt(cipher_text)
    plain_text = unpad(padded_plain_text, DES.block_size)
    return plain_text.decode()

def aes_encrypt(plain_text, key):
    """Encrypt a message using AES-256."""
    cipher = AES.new(key, AES.MODE_CBC)
    padded_text = pad(plain_text.encode(), AES.block_size)
    cipher_text = cipher.encrypt(padded_text)
    return cipher.iv, cipher_text

def aes_decrypt(iv, cipher_text, key):
    """Decrypt a message using AES-256."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plain_text = cipher.decrypt(cipher_text)
    plain_text = unpad(padded_plain_text, AES.block_size)
    return plain_text.decode()

# Test message and keys
message = "Performance Testing of Encryption Algorithms"
key_des = b'ABCDEFGH'  # DES requires a key of 8 bytes
key_aes = b'0123456789ABCDEF0123456789ABCDEF'  # AES-256 requires a key of 32 bytes

# Measure DES encryption time
start_time = time.time()
iv_des, cipher_text_des = des_encrypt(message, key_des)
end_time = time.time()
des_encrypt_time = end_time - start_time

# Measure DES decryption time
start_time = time.time()
decrypted_des = des_decrypt(iv_des, cipher_text_des, key_des)
end_time = time.time()
des_decrypt_time = end_time - start_time

# Measure AES encryption time
start_time = time.time()
iv_aes, cipher_text_aes = aes_encrypt(message, key_aes)
end_time = time.time()
aes_encrypt_time = end_time - start_time

# Measure AES decryption time
start_time = time.time()
decrypted_aes = aes_decrypt(iv_aes, cipher_text_aes, key_aes)
end_time = time.time()
aes_decrypt_time = end_time - start_time

# Output results
print(f"DES Encryption Time: {des_encrypt_time:.6f} seconds")
print(f"DES Decryption Time: {des_decrypt_time:.6f} seconds")
print(f"AES-256 Encryption Time: {aes_encrypt_time:.6f} seconds")
print(f"AES-256 Decryption Time: {aes_decrypt_time:.6f} seconds")

# Verify decrypted messages
assert decrypted_des == message, "DES Decryption failed!"
assert decrypted_aes == message, "AES Decryption failed!"
