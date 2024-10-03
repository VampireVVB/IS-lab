def vigenere_encipher(plaintext, keyword):
    """Encipher a plaintext message using the Vigenère cipher with the given keyword."""
    # Normalize inputs
    plaintext = plaintext.upper().replace(" ", "")  # Remove spaces and convert to uppercase
    keyword = keyword.upper()
    
    cipher_text = []
    keyword_repeated = (keyword * (len(plaintext) // len(keyword) + 1))[:len(plaintext)]
    
    for p_char, k_char in zip(plaintext, keyword_repeated):
        if p_char.isalpha():  # Ensure it's a letter
            # Calculate the shift for the character
            shift = ord(k_char) - ord('A')
            enc_char = chr((ord(p_char) - ord('A') + shift) % 26 + ord('A'))
            cipher_text.append(enc_char)
        else:
            cipher_text.append(p_char)  # Keep non-alphabet characters unchanged

    return ''.join(cipher_text)

# Given values
plaintext_vigenere = "Life is full of surprises"
keyword_vigenere = "HEALTH"

# Encipher the message
ciphered_message = vigenere_encipher(plaintext_vigenere, keyword_vigenere)
print(f"Enciphered message: {ciphered_message}")

# Part b - Size of the permutation key
permutation_key_size = len("abcdefghi")
print(f"Size of the permutation key: {permutation_key_size}")
