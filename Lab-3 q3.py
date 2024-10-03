from Crypto.Util.number import long_to_bytes, bytes_to_long

# Define the RSA parameters
n = 323
e = 5
d = 173

# Define the message
message = "Cryptographic Protocols"

# Function to encrypt the message using RSA
def encrypt_rsa(message, n, e):
    # Convert the message to bytes and then to a long integer
    message_bytes = message.encode()
    message_int = bytes_to_long(message_bytes)
    
    # Encrypt the message using the RSA formula: ciphertext = (message^e) mod n
    ciphertext_int = pow(message_int, e, n)
    return ciphertext_int

# Function to decrypt the ciphertext using RSA
def decrypt_rsa(ciphertext_int, n, d):
    # Decrypt the ciphertext using the RSA formula: decrypted_message = (ciphertext^d) mod n
    decrypted_int = pow(ciphertext_int, d, n)
    
    # Convert the long integer back to bytes
    decrypted_bytes = long_to_bytes(decrypted_int)
    return decrypted_bytes.decode()

# Encrypt the message
ciphertext = encrypt_rsa(message, n, e)

# Decrypt the ciphertext
decrypted_message = decrypt_rsa(ciphertext, n, d)

# Display results
print("RSA Ciphertext (as integer):", ciphertext)
print("RSA Decrypted Message:", decrypted_message)
