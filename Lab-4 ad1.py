import os
import logging
import time
from sympy import nextprime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta

# Setup logging
logging.basicConfig(filename='drm_management.log', level=logging.INFO)

class ElGamalCryptosystem:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.p = nextprime(os.urandom(self.key_size // 8).hex())
        self.g = 2
        self.x = None  # Private key
        self.y = None  # Public key

    def generate_keys(self):
        """Generate ElGamal keys."""
        self.x = os.urandom(self.key_size // 8) % (self.p - 1)
        self.y = pow(self.g, self.x, self.p)
        logging.info(f'Keys generated: (p={self.p}, g={self.g}, y={self.y})')

    def encrypt(self, plaintext):
        """Encrypt plaintext using the ElGamal public key."""
        k = os.urandom(self.key_size // 8) % (self.p - 1)  # Random k
        c1 = pow(self.g, k, self.p)
        c2 = (plaintext * pow(self.y, k, self.p)) % self.p
        return (c1, c2)

    def decrypt(self, c1, c2):
        """Decrypt the ciphertext using the private key."""
        s = pow(c1, self.x, self.p)
        plaintext = (c2 * pow(s, self.p - 2, self.p)) % self.p  # s^{-1} mod p
        return plaintext

    def store_key(self, key, filename):
        """Securely store the private key."""
        with open(filename, 'wb') as key_file:
            key_file.write(key)

    def load_key(self, filename):
        """Load the private key from secure storage."""
        with open(filename, 'rb') as key_file:
            return key_file.read()

class DRMService:
    def __init__(self):
        self.elgamal = ElGamalCryptosystem()
        self.access_controls = {}
        self.key_file = 'master_private_key.pem'
        self.elgamal.generate_keys()
        self.store_master_private_key()

    def store_master_private_key(self):
        """Store the master private key securely."""
        self.elgamal.store_key(self.elgamal.x.to_bytes(self.elgamal.key_size // 8, 'big'), self.key_file)
        logging.info('Master private key stored securely.')

    def content_encryption(self, content):
        """Encrypt the digital content using the master public key."""
        plaintext = int.from_bytes(content.encode(), 'big')
        ciphertext = self.elgamal.encrypt(plaintext)
        logging.info(f'Content encrypted: {ciphertext}')
        return ciphertext

    def grant_access(self, customer_id, content_id, duration):
        """Grant limited-time access to customers."""
        end_time = datetime.now() + timedelta(seconds=duration)
        self.access_controls[(customer_id, content_id)] = end_time
        logging.info(f'Access granted to {customer_id} for {content_id} until {end_time}.')

    def revoke_access(self, customer_id, content_id):
        """Revoke access to customers."""
        if (customer_id, content_id) in self.access_controls:
            del self.access_controls[(customer_id, content_id)]
            logging.info(f'Access revoked for {customer_id} for {content_id}.')

    def check_access(self, customer_id, content_id):
        """Check if a customer has access to specific content."""
        if (customer_id, content_id) in self.access_controls:
            end_time = self.access_controls[(customer_id, content_id)]
            if datetime.now() < end_time:
                logging.info(f'Access granted to {customer_id} for {content_id}.')
                return True
            else:
                self.revoke_access(customer_id, content_id)
                logging.warning(f'Access expired for {customer_id} for {content_id}.')
        return False

    def revoke_master_key(self):
        """Revoke the master private key."""
        self.elgamal.x = None
        logging.warning('Master private key revoked.')

    def renew_keys(self):
        """Renew the master public-private key pair."""
        self.elgamal.generate_keys()
        self.store_master_private_key()
        logging.info('Master key pair renewed.')

def main():
    drm_service = DRMService()
    
    # Simulate content encryption
    content_id = "ebook_001"
    content = "This is a digital book about ElGamal Cryptosystem."
    ciphertext = drm_service.content_encryption(content)

    # Grant access to a customer
    drm_service.grant_access('customer_1', content_id, 3600)  # 1 hour access

    # Check access
    if drm_service.check_access('customer_1', content_id):
        print("Customer has access to the content.")
    else:
        print("Access denied.")

    # Revoke access
    drm_service.revoke_access('customer_1', content_id)

    # Renew keys (simulate every 24 months)
    drm_service.renew_keys()

if __name__ == "__main__":
    main()
