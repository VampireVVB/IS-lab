import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
import binascii

def generate_dh_parameters():
    return dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

def generate_dh_private_key(parameters):
    return parameters.generate_private_key()

def generate_shared_key(private_key, peer_public_key):
    return private_key.exchange(peer_public_key)

def verify_signature(shared_key, document, signature):
    hmac = HMAC(shared_key, hashes.SHA256(), backend=default_backend())
    hmac.update(document.encode())
    try:
        hmac.verify(signature)
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

def main():
    # Connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 5000))

    # Generate Diffie-Hellman parameters and private key
    parameters = generate_dh_parameters()
    client_private_key = generate_dh_private_key(parameters)
    client_public_key = client_private_key.public_key()

    # Send public key to the server
    client_socket.send(client_public_key.public_bytes(
        encoding=dh.Encoding.DER,
        format=dh.PublicFormat.SubjectPublicKeyInfo))

    # Receive server public key
    server_public_key_bytes = client_socket.recv(1024)
    server_public_key = dh.load_public_key(server_public_key_bytes, backend=default_backend())

    # Generate shared key
    shared_key = generate_shared_key(client_private_key, server_public_key)

    # Document to be signed
    document = "This is a legal document signed by Alice."

    # Send the document to the server
    client_socket.send(document.encode())

    # Receive the signature from the server
    signature = client_socket.recv(1024)

    # Verify the signature
    if verify_signature(shared_key, document, signature):
        print("The signature is valid.")
    else:
        print("The signature is invalid.")

    # Close the connection
    client_socket.close()

if __name__ == "__main__":
    main()
