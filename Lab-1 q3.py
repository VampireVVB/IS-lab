import string

def preprocess_message(message):
    """Preprocess message: remove spaces, convert to uppercase, and replace 'J' with 'I'."""
    message = message.replace(" ", "").upper().replace('J', 'I')
    
    # Insert 'X' between repeated letters and make message even length
    processed_message = []
    i = 0
    while i < len(message):
        processed_message.append(message[i])
        if i + 1 < len(message) and message[i] == message[i + 1]:
            processed_message.append('X')  # Insert 'X' between repeated letters
        elif i + 1 >= len(message):  # If the last letter has no pair, add 'X'
            processed_message.append('X')
        i += 1

    # Ensure message length is even by adding an 'X' if necessary
    if len(processed_message) % 2 != 0:
        processed_message.append('X')

    return ''.join(processed_message)

def create_playfair_matrix(key):
    """Create the 5x5 Playfair matrix using the given key."""
    key = key.upper().replace('J', 'I')  # Treat 'I' and 'J' as the same
    matrix = []
    used_chars = set()

    # Add unique characters from the key
    for char in key:
        if char not in used_chars:
            matrix.append(char)
            used_chars.add(char)

    # Add remaining letters of the alphabet
    for char in string.ascii_uppercase:
        if char not in used_chars and char != 'J':  # Skip 'J'
            matrix.append(char)

    # Reshape matrix into a 5x5 grid
    matrix_5x5 = [matrix[i:i+5] for i in range(0, 25, 5)]
    return matrix_5x5

def find_position(matrix, char):
    """Find the row and column of a character in the Playfair matrix."""
    for row_idx, row in enumerate(matrix):
        if char in row:
            return row_idx, row.index(char)
    return None

def playfair_cipher_encrypt(message, matrix):
    """Encrypt the message using Playfair cipher with the provided key matrix."""
    encrypted_message = []
    i = 0
    while i < len(message):
        char1, char2 = message[i], message[i + 1]
        row1, col1 = find_position(matrix, char1)
        row2, col2 = find_position(matrix, char2)

        # Rule 1: Same row
        if row1 == row2:
            encrypted_message.append(matrix[row1][(col1 + 1) % 5])
            encrypted_message.append(matrix[row2][(col2 + 1) % 5])
        
        # Rule 2: Same column
        elif col1 == col2:
            encrypted_message.append(matrix[(row1 + 1) % 5][col1])
            encrypted_message.append(matrix[(row2 + 1) % 5][col2])

        # Rule 3: Rectangle rule (letters form a rectangle)
        else:
            encrypted_message.append(matrix[row1][col2])
            encrypted_message.append(matrix[row2][col1])

        i += 2  # Move to the next pair

    return ''.join(encrypted_message)

# Main
message = "The key is hidden under the door pad"
key = "GUIDANCE"

# Preprocess the message and create the Playfair matrix
processed_message = preprocess_message(message)
playfair_matrix = create_playfair_matrix(key)

# Encrypt the message
encrypted_message = playfair_cipher_encrypt(processed_message, playfair_matrix)

# Print results
print("Original message:", message)
print("Processed message:", processed_message)
print("Encrypted message:", encrypted_message)

print("\nPlayfair Matrix:")
for row in playfair_matrix:
    print(row)
