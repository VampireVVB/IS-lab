def rsa_encrypt(message, n, e):
    """Encrypts the message using RSA public key (n, e)."""
    # Convert message to numeric representation
    message_numeric = [ord(char) for char in message]
    ciphertext = [pow(m, e, n) for m in message_numeric]  # c = m^e mod n
    return ciphertext

def rsa_decrypt(ciphertext, n, d):
    """Decrypts the ciphertext using RSA private key (n, d)."""
    decrypted_message = [pow(c, d, n) for c in ciphertext]  # m = c^d mod n
    return ''.join(chr(m) for m in decrypted_message)

def main():
    # RSA parameters
    n = 323
    e = 5
    d = 173
    message = "Cryptographic Protocols"

    # Encrypt the message
    ciphertext = rsa_encrypt(message, n, e)
    print("Ciphertext (Numeric):", ciphertext)

    # Decrypt the ciphertext
    decrypted_message = rsa_decrypt(ciphertext, n, d)
    print("Decrypted Message:", decrypted_message)

if __name__ == "__main__":
    main()
