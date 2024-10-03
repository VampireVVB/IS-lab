from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
import os
import binascii

# Generate Diffie-Hellman parameters
def generate_dh_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters

# Generate DH private key
def generate_dh_private_key(parameters):
    private_key = parameters.generate_private_key()
    return private_key

# Generate shared key using the private key and peer public key
def generate_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    return shared_key

# Sign the document using HMAC
def sign_document(shared_key, document):
    hmac = HMAC(shared_key, hashes.SHA256(), backend=default_backend())
    hmac.update(document.encode())
    signature = hmac.finalize()
    return signature

# Verify the signature
def verify_signature(shared_key, document, signature):
    hmac = HMAC(shared_key, hashes.SHA256(), backend=default_backend())
    hmac.update(document.encode())
    try:
        hmac.verify(signature)
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

# Main flow
if __name__ == "__main__":
    # Step 1: Generate Diffie-Hellman parameters
    parameters = generate_dh_parameters()

    # Step 2: Generate private keys for Alice and Bob
    alice_private_key = generate_dh_private_key(parameters)
    bob_private_key = generate_dh_private_key(parameters)

    # Step 3: Generate public keys for Alice and Bob
    alice_public_key = alice_private_key.public_key()
    bob_public_key = bob_private_key.public_key()

    # Step 4: Generate shared keys
    alice_shared_key = generate_shared_key(alice_private_key, bob_public_key)
    bob_shared_key = generate_shared_key(bob_private_key, alice_public_key)

    # Ensure both shared keys are the same
    assert alice_shared_key == bob_shared_key

    # Document Alice wants to sign
    alice_document = "This is a legal document signed by Alice."

    # Alice signs the document
    alice_signature = sign_document(alice_shared_key, alice_document)
    
    # Convert the signature to hexadecimal representation for demonstration
    alice_signature_hex = binascii.hexlify(alice_signature)
    print("Alice's Digital Signature (Hex):", alice_signature_hex)

    # Now Bob verifies Alice's signature
    print("Verifying Alice's signature...")
    if verify_signature(bob_shared_key, alice_document, alice_signature):
        print("Alice's signature is valid.")
    else:
        print("Alice's signature is invalid.")
    
    # Bob creates a document and signs it
    bob_document = "This is a legal document signed by BOB."
    
    # Bob signs the document
    bob_signature = sign_document(bob_shared_key, bob_document)
    
    # Convert the signature to hexadecimal representation for demonstration
    bob_signature_hex = binascii.hexlify(bob_signature)
    print("Bob's Digital Signature (Hex):", bob_signature_hex)

    # Now Alice verifies Bob's signature
    print("Verifying Bob's signature...")
    if verify_signature(alice_shared_key, bob_document, bob_signature):
        print("Bob's signature is valid.")
    else:
        print("Bob's signature is invalid.")
