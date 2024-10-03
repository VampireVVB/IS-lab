import numpy as np

def preprocess_message(message):
    """Preprocess the message by removing spaces, converting to uppercase, and padding if necessary."""
    message = message.replace(" ", "").upper()
    
    # Ensure message length is even by adding a 'X' if necessary
    if len(message) % 2 != 0:
        message += 'X'
    
    return message

def char_to_num(char):
    """Convert a character to its corresponding number (A=0, ..., Z=25)."""
    return ord(char) - ord('A')

def num_to_char(num):
    """Convert a number (0-25) back to a character ('A' to 'Z')."""
    return chr(num % 26 + ord('A'))

def hill_cipher_encrypt(message, key_matrix):
    """Encrypt the message using the Hill cipher with the given key matrix."""
    message = preprocess_message(message)
    encrypted_message = []
    
    # Process the message in blocks of 2 characters
    for i in range(0, len(message), 2):
        # Convert each pair of characters to numbers
        pair = [char_to_num(message[i]), char_to_num(message[i + 1])]
        
        # Convert pair to a column vector
        pair_vector = np.array(pair).reshape(2, 1)
        
        # Multiply key matrix by the pair vector mod 26
        encrypted_vector = np.dot(key_matrix, pair_vector) % 26
        
        # Convert the resulting numbers back to characters
        encrypted_message.append(num_to_char(encrypted_vector[0][0]))
        encrypted_message.append(num_to_char(encrypted_vector[1][0]))
    
    return ''.join(encrypted_message)

# Main
message = "We live in an insecure world"
key_matrix = np.array([[3, 3], [2, 7]])

# Encrypt the message using Hill cipher
encrypted_message = hill_cipher_encrypt(message, key_matrix)

# Print results
print("Original message:", message)
print("Encrypted message:", encrypted_message)
