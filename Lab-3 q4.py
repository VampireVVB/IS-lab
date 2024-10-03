import time
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def generate_keys():
    """Generates a public/private key pair using the secp256r1 curve."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def elgamal_encrypt(public_key, message):
    """Encrypts a message using ElGamal encryption."""
    # Generate ephemeral key
    ephemeral_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ephemeral_pubkey = ephemeral_key.public_key()

    # Encrypt the message using the recipient's public key
    ciphertext = public_key.encrypt(
        message,
        ec.ECIES(algorithm=hashes.SHA256(), label=None)
    )
    
    return ephemeral_pubkey, ciphertext


def elgamal_decrypt(private_key, ephemeral_pubkey, ciphertext):
    """Decrypts the ciphertext using ElGamal decryption."""
    decrypted_message = private_key.decrypt(
        ciphertext,
        ec.ECIES(algorithm=hashes.SHA256(), label=None)
    )
    return decrypted_message


def measure_performance(message_size):
    """Measures encryption and decryption performance."""
    message = os.urandom(message_size)  # Generate random message of specified size
    private_key, public_key = generate_keys()

    # Measure encryption time
    start_time = time.time()
    ephemeral_pubkey, ciphertext = elgamal_encrypt(public_key, message)
    encryption_time = time.time() - start_time

    # Measure decryption time
    start_time = time.time()
    decrypted_message = elgamal_decrypt(private_key, ephemeral_pubkey, ciphertext)
    decryption_time = time.time() - start_time

    # Verify if the original message and decrypted message match
    assert message == decrypted_message, "Decrypted message does not match the original!"

    return encryption_time, decryption_time


# Example usage
if __name__ == "__main__":
    sizes = [16, 64, 256, 1024, 4096]  # Different message sizes in bytes
    for size in sizes:
        encryption_time, decryption_time = measure_performance(size)
        print(f"Message Size: {size} bytes | Encryption Time: {encryption_time:.6f} seconds | Decryption Time: {decryption_time:.6f} seconds")
