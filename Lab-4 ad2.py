from sympy import isprime, mod_inverse
import random

def generate_weak_rsa_keys():
    # Generate small prime numbers p and q
    p = 61  # Example of a small prime
    q = 53  # Example of a small prime
    n = p * q
    phi_n = (p - 1) * (q - 1)
    
    # Choose a small public exponent
    e = 17  # Common choice for e
    
    # Compute the private exponent d
    d = mod_inverse(e, phi_n)
    
    return (n, e), (p, q, d)

def rsa_encrypt(message, public_key):
    n, e = public_key
    # Convert message to an integer
    message_int = int.from_bytes(message.encode(), 'big')
    # Encrypt the message
    ciphertext = pow(message_int, e, n)
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    p, q, d = private_key
    n = p * q
    # Decrypt the ciphertext
    plaintext_int = pow(ciphertext, d, n)
    # Convert back to string
    plaintext = plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, 'big').decode()
    return plaintext

def main():
    # Generate weak RSA keys
    public_key, private_key = generate_weak_rsa_keys()
    print(f"Public Key: {public_key}")
    print(f"Private Key: (p={private_key[0]}, q={private_key[1]}, d={private_key[2]})")

    # Simulate encryption
    message = "Secure Communication"
    ciphertext = rsa_encrypt(message, public_key)
    print(f"Encrypted Message (ciphertext): {ciphertext}")

    # Eve's attack: Recover the private key from the public key
    n, e = public_key
    # Factors are already known for the weak keys
    p, q = private_key[0], private_key[1]
    
    # Calculate phi(n)
    phi_n = (p - 1) * (q - 1)
    
    # Recover private key d
    d = mod_inverse(e, phi_n)
    print(f"Eve recovered Private Key: d = {d}")

    # Decrypt the ciphertext
    decrypted_message = rsa_decrypt(ciphertext, (p, q, d))
    print(f"Decrypted Message: {decrypted_message}")

if __name__ == "__main__":
    main()
