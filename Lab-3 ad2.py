from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

def generate_ecc_keys():
    """Generate ECC public and private keys."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_message(public_key, message):
    """Encrypt the message using the public key."""
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

def decrypt_message(private_key, encrypted_symmetric_key, ciphertext):
    """Decrypt the message using the private key."""
    # Decrypt the symmetric key with the private key
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        ec.ECIES(hashes.SHA256(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), default_backend())
    )

    # Decrypt the message
    _, decrypted_message = ciphertext.split(b':', 1)

    return decrypted_message.decode()

def main():
    # Generate ECC keys
    private_key, public_key = generate_ecc_keys()

    # Message to encrypt
    message = "Secure Transactions"
    
    # Encrypt the message
    encrypted_symmetric_key, ciphertext = encrypt_message(public_key, message)
    print("Encrypted Symmetric Key (Hex):", encrypted_symmetric_key.hex())
    print("Ciphertext (Hex):", ciphertext.hex())

    # Decrypt the message
    decrypted_message = decrypt_message(private_key, encrypted_symmetric_key, ciphertext)
    print("Decrypted Message:", decrypted_message)

if __name__ == "__main__":
    main()
