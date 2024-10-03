import socket
import hashlib

def compute_hash(data):
    """Computes the SHA-256 hash of the given data."""
    return hashlib.sha256(data).hexdigest()

def start_client():
    # Create a TCP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    client_socket.connect(('localhost', 65432))

    # The data to be sent
    data_to_send = b"Hello, this is a message."
    
    # Compute the hash of the data before sending
    computed_hash = compute_hash(data_to_send)
    
    print(f"Sending data: {data_to_send.decode()}")
    print(f"Computed hash before sending: {computed_hash}")
    
    # Send data to the server
    client_socket.sendall(data_to_send)

    # Receive the hash from the server
    received_hash = client_socket.recv(64).decode()
    print(f"Received hash from server: {received_hash}")
    
    # Verify the integrity of the data
    if received_hash == computed_hash:
        print("Data integrity verified: Hashes match.")
    else:
        print("Data integrity compromised: Hashes do not match.")

    # Close the socket
    client_socket.close()

if __name__ == "__main__":
    start_client()
