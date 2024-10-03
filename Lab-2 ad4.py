from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.Padding import pad, unpad
import binascii

# Define the key, nonce, and message
key = b"0123456789ABCDEF0123456789ABCDEF"  # 32 bytes for AES-256
nonce = b"0000000000000000"  # 16 bytes nonce for AES
message = "Cryptography Lab Exercise"

# Function to encrypt using AES in CTR mode
def encrypt_aes_ctr(message, key, nonce):
    ctr = Counter.new(128, prefix=nonce, initial_value=0)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    ciphertext = cipher.encrypt(message.encode())
    return ciphertext

# Function to decrypt using AES in CTR mode
def decrypt_aes_ctr(ciphertext, key, nonce):
    ctr = Counter.new(128, prefix=nonce, initial_value=0)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    decrypted_message = cipher.decrypt(ciphertext)
    return decrypted_message

# Encrypt the message
ciphertext = encrypt_aes_ctr(message, key, nonce)

# Decrypt the ciphertext
decrypted_message = decrypt_aes_ctr(ciphertext, key, nonce)

# Display results
print("AES CTR Ciphertext:", binascii.hexlify(ciphertext).decode())
print("AES CTR Decrypted Message:", decrypted_message.decode())
