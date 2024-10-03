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

### Vigenere Cipher Functions
def vigenere_cipher_encrypt(message, key):
    """Encrypt message using the Vigenere Cipher with the given key"""
    message = preprocess_message(message)
    key = preprocess_message(key)
    key_length = len(key)
    encrypted_message = []
    
    for i, char in enumerate(message):
        key_char = key[i % key_length]  # Repeat key cyclically
        shift = char_to_num(key_char)
        encrypted_message.append(num_to_char((char_to_num(char) + shift) % 26))
    
    return ''.join(encrypted_message)

def vigenere_cipher_decrypt(cipher, key):
    """Decrypt message using the Vigenere Cipher with the given key"""
    cipher = preprocess_message(cipher)
    key = preprocess_message(key)
    key_length = len(key)
    decrypted_message = []
    
    for i, char in enumerate(cipher):
        key_char = key[i % key_length]  # Repeat key cyclically
        shift = char_to_num(key_char)
        decrypted_message.append(num_to_char((char_to_num(char) - shift) % 26))
    
    return ''.join(decrypted_message)

### Autokey Cipher Functions
def autokey_cipher_encrypt(message, key):
    """Encrypt message using the Autokey Cipher with the given key (an integer)"""
    message = preprocess_message(message)
    encrypted_message = []
    full_key = [key] + [char_to_num(c) for c in message]  # Start with key, then append message

    for i, char in enumerate(message):
        shift = full_key[i]
        encrypted_message.append(num_to_char((char_to_num(char) + shift) % 26))

    return ''.join(encrypted_message)

def autokey_cipher_decrypt(cipher, key):
    """Decrypt message using the Autokey Cipher with the given key (an integer)"""
    cipher = preprocess_message(cipher)
    decrypted_message = []
    full_key = [key]  # Start with the given key

    for i, char in enumerate(cipher):
        shift = full_key[i]  # Use previous shift or key
        decrypted_char = num_to_char((char_to_num(char) - shift) % 26)
        decrypted_message.append(decrypted_char)
        full_key.append(char_to_num(decrypted_char))  # Append decrypted char to key

    return ''.join(decrypted_message)

# Get user input for the message
message = input("Enter the message: ")

# Vigenere Cipher
vigenere_key = "dollars"
vigenere_encrypted = vigenere_cipher_encrypt(message, vigenere_key)
vigenere_decrypted = vigenere_cipher_decrypt(vigenere_encrypted, vigenere_key)

# Autokey Cipher
autokey_key = 7
autokey_encrypted = autokey_cipher_encrypt(message, autokey_key)
autokey_decrypted = autokey_cipher_decrypt(autokey_encrypted, autokey_key)

# Print results
print("\nVigenere Cipher:")
print("Encrypted:", vigenere_encrypted)
print("Decrypted:", vigenere_decrypted)

print("\nAutokey Cipher:")
print("Encrypted:", autokey_encrypted)
print("Decrypted:", autokey_decrypted)
