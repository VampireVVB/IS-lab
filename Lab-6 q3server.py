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

def sign_document(shared_key, document):
    hmac = HMAC(shared_key, hashes.SHA256(), backend=default_backend())
    hmac.update(document.encode())
    return hmac.finalize()

def main():
    # Create a socket server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 5000))
    server_socket.listen(1)
    print("Server is listening on port 5000...")

    # Generate Diffie-Hellman parameters and private key
    parameters = generate_dh_parameters()
    server_private_key = generate_dh_private_key(parameters)
    server_public_key = server_private_key.public_key()

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection established with {addr}")

        # Send public key to the client
        client_public_key_bytes = client_socket.recv(1024)
        client_public_key = dh.load_public_key(client_public_key_bytes, backend=default_backend())

        # Generate shared key
        shared_key = generate_shared_key(server_private_key, client_public_key)

        # Receive the document
        document = client_socket.recv(1024).decode()
        print(f"Received document: {document}")

        # Sign the document
        signature = sign_document(shared_key, document)

        # Send the signature back to the client
        client_socket.send(signature)

        # Close client connection
        client_socket.close()

if __name__ == "__main__":
    main()
