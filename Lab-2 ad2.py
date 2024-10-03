from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import binascii

# Define the key and the blocks of data
key = b"A1B2C3D4E5F60708"  # 16 bytes, DES requires 8 bytes, will take first 8 bytes
block1_hex = "54686973206973206120636f6e666964656e7469616c206d657373616765"
block2_hex = "416e64207468697320697320746865207365636f6e6420626c6f636b"

# Convert hex to bytes
block1 = binascii.unhexlify(block1_hex)
block2 = binascii.unhexlify(block2_hex)

# Function to encrypt a block using DES
def encrypt_des(data, key):
    cipher = DES.new(key[:8], DES.MODE_ECB)  # Use first 8 bytes for DES
    padded_data = pad(data, DES.block_size)  # Pad the data to be a multiple of 8
    ciphertext = cipher.encrypt(padded_data)
    return ciphertext

# Function to decrypt a block using DES
def decrypt_des(ciphertext, key):
    cipher = DES.new(key[:8], DES.MODE_ECB)  # Use first 8 bytes for DES
    decrypted_data = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return decrypted_data

# Encrypt the blocks
ciphertext_block1 = encrypt_des(block1, key)
ciphertext_block2 = encrypt_des(block2, key)

# Decrypt the ciphertexts
decrypted_block1 = decrypt_des(ciphertext_block1, key)
decrypted_block2 = decrypt_des(ciphertext_block2, key)

# Display results
print("Ciphertext for Block 1:", binascii.hexlify(ciphertext_block1).decode())
print("Ciphertext for Block 2:", binascii.hexlify(ciphertext_block2).decode())
print("Decrypted Block 1:", decrypted_block1.decode())
print("Decrypted Block 2:", decrypted_block2.decode())
