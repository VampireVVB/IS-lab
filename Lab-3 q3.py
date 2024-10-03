import random
from sympy import mod_inverse

# Function to generate a prime number (for simplicity, using a small prime)
def generate_prime():
    return 23  # p (a small prime for demonstration)

# Function to generate ElGamal keys
def generate_keys():
    p = generate_prime()
    g = 5  # Generator
    x = random.randint(1, p - 2)  # Private key
    h = pow(g, x, p)  # Public key component
    return (p, g, h), x  # Public key (p, g, h) and private key x

# Function to encrypt a message using ElGamal
def elgamal_encrypt(public_key, message):
    p, g, h = public_key
    k = random.randint(1, p - 2)  # Random integer k
    c1 = pow(g, k, p)  # c1 = g^k mod p
    c2 = (pow(h, k, p) * int.from_bytes(message.encode(), 'big')) % p  # c2 = (h^k * m) mod p
    return c1, c2

# Function to decrypt a message using ElGamal
def elgamal_decrypt(private_key, ciphertext, public_key):
    p, _, _ = public_key
    x = private_key
    c1, c2 = ciphertext
    s = pow(c1, x, p)  # s = c1^x mod p
    s_inv = mod_inverse(s, p)  # s_inv = s^(-1) mod p
    m = (c2 * s_inv) % p  # m = (c2 * s_inv) mod p
    return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()  # Convert back to string

# Example usage
if __name__ == "__main__":
    # Generate keys
    public_key, private_key = generate_keys()
    
    # Encrypt the message
    message = "Confidential Data"
    ciphertext = elgamal_encrypt(public_key, message)
    
    # Decrypt the ciphertext
    decrypted_message = elgamal_decrypt(private_key, ciphertext, public_key)
    
    # Display results
    print("Original Message:", message)
    print("Ciphertext (c1, c2):", ciphertext)
    print("Decrypted Message:", decrypted_message)

