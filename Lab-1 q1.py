# Helper functions to handle common operations
def char_to_num(char):
    """Convert a character to its corresponding number (A=0, B=1, ..., Z=25)"""
    return ord(char.upper()) - ord('A')

def num_to_char(num):
    """Convert a number (0-25) back to a character ('A' to 'Z')"""
    return chr((num % 26) + ord('A'))

def preprocess_message(message):
    """Remove spaces and convert to uppercase"""
    return message.replace(" ", "").upper()

# Encryption and Decryption for Additive Cipher
def additive_cipher_encrypt(message, key):
    """Encrypt the message using Additive Cipher with the given key"""
    return ''.join([num_to_char((char_to_num(c) + key) % 26) for c in message])

def additive_cipher_decrypt(cipher, key):
    """Decrypt the message using Additive Cipher with the given key"""
    return ''.join([num_to_char((char_to_num(c) - key) % 26) for c in cipher])

# Encryption and Decryption for Multiplicative Cipher
def multiplicative_cipher_encrypt(message, key):
    """Encrypt the message using Multiplicative Cipher with the given key"""
    return ''.join([num_to_char((char_to_num(c) * key) % 26) for c in message])

def multiplicative_cipher_decrypt(cipher, key):
    """Decrypt the message using Multiplicative Cipher with the given key"""
    mod_inverse_key = pow(key, -1, 26)  # Modular inverse of key
    return ''.join([num_to_char((char_to_num(c) * mod_inverse_key) % 26) for c in cipher])

# Encryption and Decryption for Affine Cipher
def affine_cipher_encrypt(message, a, b):
    """Encrypt the message using Affine Cipher with keys a (multiplicative) and b (additive)"""
    return ''.join([num_to_char((char_to_num(c) * a + b) % 26) for c in message])

def affine_cipher_decrypt(cipher, a, b):
    """Decrypt the message using Affine Cipher with keys a (multiplicative) and b (additive)"""
    mod_inverse_a = pow(a, -1, 26)  # Modular inverse of 'a'
    return ''.join([num_to_char((mod_inverse_a * (char_to_num(c) - b)) % 26) for c in cipher])

# Test the ciphers with the provided message
message = "I am learning information security"
preprocessed_message = preprocess_message(message)

# Define keys
additive_key = 20
multiplicative_key = 15
affine_a, affine_b = 15, 20

# Encryptions
additive_encrypted = additive_cipher_encrypt(preprocessed_message, additive_key)
multiplicative_encrypted = multiplicative_cipher_encrypt(preprocessed_message, multiplicative_key)
affine_encrypted = affine_cipher_encrypt(preprocessed_message, affine_a, affine_b)

# Decryptions
additive_decrypted = additive_cipher_decrypt(additive_encrypted, additive_key)
multiplicative_decrypted = multiplicative_cipher_decrypt(multiplicative_encrypted, multiplicative_key)
affine_decrypted = affine_cipher_decrypt(affine_encrypted, affine_a, affine_b)

# Print results
print("Additive Cipher:")
print("Encrypted:", additive_encrypted)
print("Decrypted:", additive_decrypted)

print("\nMultiplicative Cipher:")
print("Encrypted:", multiplicative_encrypted)
print("Decrypted:", multiplicative_decrypted)

print("\nAffine Cipher:")
print("Encrypted:", affine_encrypted)
print("Decrypted:", affine_decrypted)
