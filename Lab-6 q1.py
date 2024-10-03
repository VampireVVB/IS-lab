from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import binascii

# Step 1: Generate RSA Key Pair
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Step 2: Sign the Document
def sign_document(private_key, document):
    signature = private_key.sign(
        document.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Step 3: Verify Digital Signature
def verify_signature(public_key, document, signature):
    try:
        public_key.verify(
            signature,
            document.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

# Step 4: Main flow
if __name__ == "__main__":
    # Generate keys for Alice
    alice_private_key, alice_public_key = generate_keys()

    # Document Alice wants to sign
    alice_document = "This is a legal document signed by Alice."
    
    # Alice signs the document
    alice_signature = sign_document(alice_private_key, alice_document)
    
    # Convert the signature to hexadecimal representation for demonstration
    alice_signature_hex = binascii.hexlify(alice_signature)
    print("Alice's Digital Signature (Hex):", alice_signature_hex)

    # Now Bob verifies Alice's signature
    print("Verifying Alice's signature...")
    if verify_signature(alice_public_key, alice_document, alice_signature):
        print("Alice's signature is valid.")
    else:
        print("Alice's signature is invalid.")
    
    # Bob creates a document and signs it
    bob_private_key, bob_public_key = generate_keys()
    bob_document = "This is a legal document signed by BOB."
    
    # Bob signs the document
    bob_signature = sign_document(bob_private_key, bob_document)
    
    # Convert the signature to hexadecimal representation for demonstration
    bob_signature_hex = binascii.hexlify(bob_signature)
    print("Bob's Digital Signature (Hex):", bob_signature_hex)

    # Now Alice verifies Bob's signature
    print("Verifying Bob's signature...")
    if verify_signature(bob_public_key, bob_document, bob_signature):
        print("Bob's signature is valid.")
    else:
        print("Bob's signature is invalid.")
