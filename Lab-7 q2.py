import random
import math

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

def generate_keypair(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Choose e such that 1 < e < phi and gcd(e, phi) == 1
    e = 3  # Common choice for e
    while gcd(e, phi) != 1:
        e += 2
    
    # Compute d, the modular inverse of e
    d = mod_inverse(e, phi)
    
    return (e, n), (d, n)

def encrypt(plain, pubkey):
    e, n = pubkey
    # c = m^e mod n
    return pow(plain, e, n)

def decrypt(cipher, privkey):
    d, n = privkey
    # m = c^d mod n
    return pow(cipher, d, n)

def main():
    # Generate RSA keys
    p = 61  # First prime
    q = 53  # Second prime
    public_key, private_key = generate_keypair(p, q)

    # Original integers
    m1 = 7
    m2 = 3

    # Encrypt the integers
    c1 = encrypt(m1, public_key)
    c2 = encrypt(m2, public_key)

    print(f"Ciphertext of {m1}: {c1}")
    print(f"Ciphertext of {m2}: {c2}")

    # Multiply the ciphertexts (homomorphic property)
    c_product = (c1 * c2) % public_key[1]
    print(f"Ciphertext of the product: {c_product}")

    # Decrypt the result of the multiplication
    decrypted_product = decrypt(c_product, private_key)
    print(f"Decrypted product: {decrypted_product}")

    # Verify the multiplication
    print(f"Original product: {m1 * m2}")

if __name__ == "__main__":
    main()
