import os
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def generate_keys():
    """Generate public and private keys using secp256r1 curve."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def elgamal_encrypt(public_key, message):
    """Encrypt the message using ElGamal encryption."""
    # Generate a random symmetric key (for example, a 256-bit AES key)
    symmetric_key = os.urandom(32)

    # Encrypt the message using the symmetric key
    ciphertext = symmetric_key + b':' + message.encode()

    # Encrypt the symmetric key with the public key
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        ec.ECIES(hashes.SHA256(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), default_backend())
    )

    return encrypted_symmetric_key, ciphertext

def elgamal_decrypt(private_key, encrypted_symmetric_key, ciphertext):
    """Decrypt the message using ElGamal decryption."""
    # Decrypt the symmetric key with the private key
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        ec.ECIES(hashes.SHA256(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), default_backend())
    )

    # Decrypt the message
    _, decrypted_message = ciphertext.split(b':', 1)

    return decrypted_message.decode()

def measure_performance(data_sizes):
    """Measure the performance of encryption and decryption processes."""
    for size in data_sizes:
        message = 'A' * size  # Create a message of specified size

        # Generate keys
        private_key, public_key = generate_keys()

        # Measure encryption time
        start_time = time.time()
        encrypted_symmetric_key, ciphertext = elgamal_encrypt(public_key, message)
        encryption_time = time.time() - start_time

        # Measure decryption time
        start_time = time.time()
        decrypted_message = elgamal_decrypt(private_key, encrypted_symmetric_key, ciphertext)
        decryption_time = time.time() - start_time

        print(f"Data Size: {size} bytes | Encryption Time: {encryption_time:.6f} seconds | Decryption Time: {decryption_time:.6f} seconds | Original Message: {decrypted_message}")

def main():
    data_sizes = [64, 128, 256, 512, 1024]  # Different sizes of patient data to test
    measure_performance(data_sizes)

if __name__ == "__main__":
    main()
