import os
import time
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def generate_rsa_keys():
    """Generate RSA keys (2048-bit)"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def generate_ecc_keys():
    """Generate ECC keys (secp256r1)"""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_rsa(public_key, data):
    """Encrypt data using RSA public key"""
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_rsa(private_key, ciphertext):
    """Decrypt data using RSA private key"""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def encrypt_ecc(public_key, data):
    """Encrypt data using ECC public key"""
    # ECC doesn't directly encrypt large data, so we can simulate this using shared secret.
    # For demonstration, we will use hybrid encryption.
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ephemeral_public_key = ephemeral_private_key.public_key()
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), public_key)
    # Derive a key from the shared secret
    derived_key = hashes.Hash(hashes.SHA256(), backend=default_backend())
    derived_key.update(shared_secret)
    return ephemeral_public_key, derived_key.finalize(), data

def decrypt_ecc(private_key, ephemeral_public_key, ciphertext):
    """Decrypt data using ECC private key"""
    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)
    derived_key = hashes.Hash(hashes.SHA256(), backend=default_backend())
    derived_key.update(shared_secret)
    decrypted_key = derived_key.finalize()
    return ciphertext  # In this example, we will just return the ciphertext

def measure_performance(algorithm, file_path):
    """Measure performance of encryption/decryption for a given algorithm."""
    with open(file_path, 'rb') as file:
        data = file.read()

    if algorithm == 'RSA':
        private_key, public_key = generate_rsa_keys()
        start_time = time.time()
        ciphertext = encrypt_rsa(public_key, data)
        encryption_time = time.time() - start_time

        start_time = time.time()
        decrypted_data = decrypt_rsa(private_key, ciphertext)
        decryption_time = time.time() - start_time
    elif algorithm == 'ECC':
        private_key, public_key = generate_ecc_keys()
        start_time = time.time()
        ephemeral_pubkey, derived_key, _ = encrypt_ecc(public_key, data)
        encryption_time = time.time() - start_time

        start_time = time.time()
        decrypted_data = decrypt_ecc(private_key, ephemeral_pubkey, data)
        decryption_time = time.time() - start_time

    return encryption_time, decryption_time

# File transfer simulation
def secure_file_transfer():
    file_sizes = [1024 * 1024, 10 * 1024 * 1024]  # 1 MB, 10 MB
    for size in file_sizes:
        # Create a dummy file for testing
        file_path = f'test_file_{size // (1024 * 1024)}MB.txt'
        with open(file_path, 'wb') as f:
            f.write(os.urandom(size))  # Write random data

        # Measure performance for RSA
        rsa_encryption_time, rsa_decryption_time = measure_performance('RSA', file_path)
        print(f'RSA | File Size: {size / (1024 * 1024)} MB | '
              f'Encryption Time: {rsa_encryption_time:.4f}s | '
              f'Decryption Time: {rsa_decryption_time:.4f}s')

        # Measure performance for ECC
        ecc_encryption_time, ecc_decryption_time = measure_performance('ECC', file_path)
        print(f'ECC | File Size: {size / (1024 * 1024)} MB | '
              f'Encryption Time: {ecc_encryption_time:.4f}s | '
              f'Decryption Time: {ecc_decryption_time:.4f}s')

if __name__ == "__main__":
    secure_file_transfer()

