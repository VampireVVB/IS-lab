import os
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def generate_rsa_keys():
    """Generate RSA public and private keys."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(public_key, message):
    """Encrypt the message using RSA encryption."""
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(private_key, ciphertext):
    """Decrypt the ciphertext using RSA decryption."""
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def generate_elgamal_keys():
    """Generate ElGamal public and private keys using secp256r1 curve."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def elgamal_encrypt(public_key, message):
    """Encrypt the message using ElGamal encryption."""
    # Generate a random symmetric key (for example, a 256-bit AES key)
    symmetric_key = os.urandom(32)

    # Encrypt the message using the symmetric key
    ciphertext = symmetric_key + b':' + message.encode()

    # Encrypt the symmetric key with the public key (using ECDH for key exchange)
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        ec.ECIES(hashes.SHA256(), default_backend())
    )

    return encrypted_symmetric_key, ciphertext

def elgamal_decrypt(private_key, encrypted_symmetric_key, ciphertext):
    """Decrypt the message using ElGamal decryption."""
    # Decrypt the symmetric key with the private key
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        ec.ECIES(hashes.SHA256(), default_backend())
    )

    # Decrypt the message
    _, decrypted_message = ciphertext.split(b':', 1)

    return decrypted_message.decode()

def measure_rsa_performance(data_sizes):
    """Measure the performance of RSA for different data sizes."""
    print("\n--- RSA Performance ---")
    for size in data_sizes:
        message = os.urandom(size)  # Create a random message of specified size

        # Measure key generation time
        start_time = time.time()
        private_key, public_key = generate_rsa_keys()
        key_generation_time = time.time() - start_time

        # Measure encryption time
        start_time = time.time()
        ciphertext = rsa_encrypt(public_key, message)
        encryption_time = time.time() - start_time

        # Measure decryption time
        start_time = time.time()
        decrypted_message = rsa_decrypt(private_key, ciphertext)
        decryption_time = time.time() - start_time

        assert message == decrypted_message, "Decryption failed!"
        
        print(f"RSA - Data Size: {size} bytes | Key Generation Time: {key_generation_time:.6f} seconds | Encryption Time: {encryption_time:.6f} seconds | Decryption Time: {decryption_time:.6f} seconds")

def measure_elgamal_performance(data_sizes):
    """Measure the performance of ElGamal for different data sizes."""
    print("\n--- ElGamal Performance ---")
    for size in data_sizes:
        message = os.urandom(size).decode(errors='ignore')  # Create a random message of specified size

        # Measure key generation time
        start_time = time.time()
        private_key, public_key = generate_elgamal_keys()
        key_generation_time = time.time() - start_time

        # Measure encryption time
        start_time = time.time()
        encrypted_symmetric_key, ciphertext = elgamal_encrypt(public_key, message)
        encryption_time = time.time() - start_time

        # Measure decryption time
        start_time = time.time()
        decrypted_message = elgamal_decrypt(private_key, encrypted_symmetric_key, ciphertext)
        decryption_time = time.time() - start_time

        assert message == decrypted_message, "Decryption failed!"
        
        print(f"ElGamal - Data Size: {size} bytes | Key Generation Time: {key_generation_time:.6f} seconds | Encryption Time: {encryption_time:.6f} seconds | Decryption Time: {decryption_time:.6f} seconds")

def main():
    data_sizes = [1024, 10240]  # 1 KB and 10 KB
    measure_rsa_performance(data_sizes)
    measure_elgamal_performance(data_sizes)

if __name__ == "__main__":
    main()
