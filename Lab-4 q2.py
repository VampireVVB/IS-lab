import os
import logging
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from sympy import nextprime

# Setup logging
logging.basicConfig(filename='key_management.log', level=logging.INFO)

class RabinCryptosystem:
    def __init__(self, key_size=1024):
        self.key_size = key_size
        self.private_keys = {}
        self.public_keys = {}
        
    def generate_keys(self):
        """Generate a public and private key pair for the Rabin cryptosystem."""
        p = nextprime(os.urandom(self.key_size // 8).hex())
        q = nextprime(os.urandom(self.key_size // 8).hex())
        n = p * q
        # Public key is n
        self.public_keys[n] = (p, q)
        return n, p, q

    def encrypt(self, plaintext, n):
        """Encrypt a plaintext message using the public key n."""
        plaintext = int.from_bytes(plaintext.encode(), 'big')
        ciphertext = (plaintext ** 2) % n
        return ciphertext

    def decrypt(self, ciphertext, p, q):
        """Decrypt a ciphertext using the private keys p and q."""
        m1 = pow(ciphertext, (p + 1) // 4, p)
        m2 = p - m1
        m3 = pow(ciphertext, (q + 1) // 4, q)
        m4 = q - m3
        
        return [m1, m2, m3, m4]

    def store_key(self, key, name):
        """Store the key securely."""
        with open(f'{name}_private_key.pem', 'wb') as key_file:
            key_file.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL
            ))
        logging.info(f'Private key stored for {name}.')

class KeyManagementService:
    def __init__(self):
        self.rabin = RabinCryptosystem()
        
    def key_generation(self, facility_name):
        """Generate keys for a hospital or clinic."""
        n, p, q = self.rabin.generate_keys()
        self.rabin.private_keys[facility_name] = (p, q)
        self.rabin.store_key(rabin, facility_name)
        logging.info(f'Keys generated for {facility_name} with public key: {n}.')
        return n

    def key_distribution(self, facility_name):
        """Provide keys to the hospital or clinic."""
        if facility_name in self.rabin.public_keys:
            public_key = self.rabin.public_keys[facility_name]
            logging.info(f'Keys distributed to {facility_name}.')
            return public_key
        else:
            logging.warning(f'No keys found for {facility_name}.')
            return None

    def revoke_key(self, facility_name):
        """Revoke keys of a hospital or clinic."""
        if facility_name in self.rabin.private_keys:
            del self.rabin.private_keys[facility_name]
            del self.rabin.public_keys[facility_name]
            logging.info(f'Keys revoked for {facility_name}.')
        else:
            logging.warning(f'No keys to revoke for {facility_name}.')

    def renew_keys(self, facility_name):
        """Renew keys of a hospital or clinic."""
        self.revoke_key(facility_name)
        self.key_generation(facility_name)
        logging.info(f'Keys renewed for {facility_name}.')

def main():
    kms = KeyManagementService()
    
    # Generate keys for hospitals and clinics
    for facility in ["Hospital A", "Clinic B", "Hospital C"]:
        kms.key_generation(facility)
    
    # Distribute keys
    for facility in ["Hospital A", "Clinic B", "Hospital C"]:
        public_key = kms.key_distribution(facility)
        print(f"{facility} Public Key: {public_key}")
    
    # Revoke keys for a facility
    kms.revoke_key("Clinic B")

    # Renew keys for a facility
    kms.renew_keys("Hospital A")

if __name__ == "__main__":
    main()
