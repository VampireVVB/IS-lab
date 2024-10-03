import random
from sympy import mod_inverse

def elgamal_encrypt(p, g, h, message):
    """Encrypts the message using ElGamal encryption."""
    # Convert message to numeric representation
    message_numeric = [ord(char) for char in message]
    ciphertext = []
    
    for m in message_numeric:
        # Generate a random k (1 < k < p) such that gcd(k, p-1) = 1
        while True:
            k = random.randint(1, p - 1)
            if pow(g, k, p) != 1:  # Check gcd(g^k, p) == 1
                break
        
        # Calculate ciphertext components
        c1 = pow(g, k, p)
        c2 = (m * pow(h, k, p)) % p
        ciphertext.append((c1, c2))
    
    return ciphertext

def elgamal_decrypt(p, x, ciphertext):
    """Decrypts the ciphertext using ElGamal decryption."""
    decrypted_message = []
    
    for c1, c2 in ciphertext:
        # Compute the shared secret
        s = pow(c1, x, p)  # s = c1^x mod p
        s_inv = mod_inverse(s, p)  # s_inv = s^-1 mod p
        
        # Decrypt the message
        m = (c2 * s_inv) % p  # m = c2 * s_inv mod p
        decrypted_message.append(chr(m))
    
    return ''.join(decrypted_message)

def main():
    # Given parameters
    p = 7919
    g = 2
    h = 6465
    x = 2999
    message = "Asymmetric Algorithms"

    # Encrypt the message
    ciphertext = elgamal_encrypt(p, g, h, message)
    print("Ciphertext:")
    for c1, c2 in ciphertext:
        print(f"({c1}, {c2})")

    # Decrypt the ciphertext
    decrypted_message = elgamal_decrypt(p, x, ciphertext)
    print("Decrypted Message:", decrypted_message)

if __name__ == "__main__":
    main()
