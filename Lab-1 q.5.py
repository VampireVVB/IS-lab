def char_to_num(char):
    """Convert a character to its corresponding number (A=0, B=1, ..., Z=25)"""
    return ord(char.upper()) - ord('A')

def num_to_char(num):
    """Convert a number (0-25) back to a character ('A' to 'Z')"""
    return chr((num % 26) + ord('A'))

def find_shift(ciphertext, plaintext):
    """Find the shift used in the shift cipher"""
    shift_values = []
    for c, p in zip(ciphertext, plaintext):
        shift = (char_to_num(c) - char_to_num(p)) % 26
        shift_values.append(shift)
    
    # Assuming all shifts are the same (it's a shift cipher)
    return shift_values[0] if len(set(shift_values)) == 1 else None

def decrypt_with_shift(ciphertext, shift):
    """Decrypt a ciphertext using a given shift"""
    decrypted_message = []
    for char in ciphertext:
        decrypted_message.append(num_to_char(char_to_num(char) - shift))
    return ''.join(decrypted_message)

# Given ciphertext and plaintext
ciphertext_example = "CIW"
plaintext_example = "yes"

# Find the shift value
shift = find_shift(ciphertext_example, plaintext_example)
if shift is not None:
    print(f"Shift used: {shift}")
else:
    print("Inconsistent shifts found.")

# Second ciphertext to decrypt
ciphertext_tablet = "XVIEWYWI"

# Decrypt the second ciphertext using the found shift
if shift is not None:
    decrypted_message = decrypt_with_shift(ciphertext_tablet, shift)
    print(f"Decrypted message: {decrypted_message}")
