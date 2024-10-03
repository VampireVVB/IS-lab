import random
import sympy

class Paillier:
    def __init__(self, bit_length=512):
        # Key Generation
        self.p = sympy.randprime(2**(bit_length-1), 2**bit_length)
        self.q = sympy.randprime(2**(bit_length-1), 2**bit_length)
        self.n = self.p * self.q
        self.n_square = self.n * self.n
        self.g = self.n + 1  # g = n + 1
        self.lambda_ = (self.p - 1) * (self.q - 1) // sympy.gcd(self.p - 1, self.q - 1)

    def encrypt(self, m):
        # m must be in the range [0, n-1]
        r = random.randint(1, self.n - 1)  # random r in [1, n-1]
        c = (pow(self.g, m, self.n_square) * pow(r, self.n, self.n_square)) % self.n_square
        return c

    def decrypt(self, c):
        # Decrypts the ciphertext c
        u = pow(c, self.lambda_, self.n_square)
        l = (u - 1) // self.n
        m = (l * sympy.mod_inverse(self.lambda_, self.n)) % self.n
        return m

    def add(self, c1, c2):
        # Homomorphic addition: c1 + c2 mod n^2
        return (c1 * c2) % self.n_square

def main():
    # Create a Paillier instance
    paillier = Paillier()

    # Original integers
    m1 = 15
    m2 = 25

    # Encrypt the integers
    c1 = paillier.encrypt(m1)
    c2 = paillier.encrypt(m2)

    print(f"Ciphertext of {m1}: {c1}")
    print(f"Ciphertext of {m2}: {c2}")

    # Homomorphic addition
    c_sum = paillier.add(c1, c2)
    print(f"Ciphertext of the sum: {c_sum}")

    # Decrypt the result of the addition
    decrypted_sum = paillier.decrypt(c_sum)
    print(f"Decrypted sum: {decrypted_sum}")

    # Verify the addition
    print(f"Original sum: {m1 + m2}")

if __name__ == "__main__":
    main()
