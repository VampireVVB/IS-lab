def char_to_num(char):
    """Convert a character to its corresponding number (A=0, B=1, ..., Z=25)"""
    return ord(char.upper()) - ord('A')

def num_to_char(num):
    """Convert a number (0-25) back to a character ('A' to 'Z')"""
    return chr((num % 26) + ord('A'))

def additive_decrypt(ciphertext, key):
    """Decrypt ciphertext using an additive cipher with the given key"""
    decrypted_message = []
    for char in ciphertext:
        if char.isalpha():  # Decrypt only letters
            y = char_to_num(char)  # C
            x = (y - key) % 26  # P
            decrypted_message.append(num_to_char(x))
        else:
            decrypted_message.append(char)  # Keep non-alphabet characters unchanged
            
    return ''.join(decrypted_message)

# Ciphertext to decrypt
ciphertext = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"

# Possible keys around Alice's birthday (13th)
possible_keys = [11, 12, 13, 14, 15]

# Try all possible keys
for key in possible_keys:
    decrypted_message = additive_decrypt(ciphertext, key)
    print(f"Trying key = {key}: Decrypted message = {decrypted_message}")
