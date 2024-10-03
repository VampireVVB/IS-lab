def char_to_num(char):
    """Convert a character to its corresponding number (A=0, B=1, ..., Z=25)"""
    return ord(char.upper()) - ord('A')

def num_to_char(num):
    """Convert a number (0-25) back to a character ('A' to 'Z')"""
    return chr((num % 26) + ord('A'))

def mod_inverse(a, m):
    """Find the modular inverse of a under modulo m"""
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None

def affine_decrypt(ciphertext, a, b):
    """Decrypt ciphertext using an affine cipher with given a and b"""
    decrypted_message = []
    a_inv = mod_inverse(a, 26)  # Get modular inverse of a
    if a_inv is None:
        return None  # No valid inverse, skip this (invalid a)
    
    for char in ciphertext:
        if char.isalpha():  # Decrypt only letters
            y = char_to_num(char)  # C
            x = (a_inv * (y - b)) % 26  # P
            decrypted_message.append(num_to_char(x))
        else:
            decrypted_message.append(char)  # Keep non-alphabet characters unchanged
            
    return ''.join(decrypted_message)

# Ciphertext to decrypt
ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"

# Known plaintext to ciphertext mapping (for "ab" to "GL")
known_plaintext = "ab"
known_ciphertext = "GL"

# Given mappings
b = 6  # Derived from 'G' = b
possible_a_values = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]

# Try all possible combinations of a and b
for a in possible_a_values:
    if (a + b) % 26 == 11:  # Check if it can yield L for b = 6
        decrypted_message = affine_decrypt(ciphertext, a, b)
        print(f"Trying a = {a}, b = {b}: Decrypted message = {decrypted_message}")
