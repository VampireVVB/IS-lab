import socket
import hashlib

def compute_hash(data):
    """Computes the SHA-256 hash of the given data."""
    return hashlib.sha256(data).hexdigest()

def start_server():
    # Create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Bind the socket to an address and port
    server_socket.bind(('localhost', 65432))
    
    # Listen for incoming connections
    server_socket.listen()
    print("Server is listening for connections...")

    # Accept a connection
    conn, addr = server_socket.accept()
    with conn:
        print(f"Connected by {addr}")
        
        # Receive data from the client
        data = conn.recv(1024)
        print(f"Received data: {data.decode()}")
        
        # Compute the hash of the received data
        data_hash = compute_hash(data)
        print(f"Computed hash: {data_hash}")
        
        # Send the hash back to the client
        conn.sendall(data_hash.encode())

if __name__ == "__main__":
    start_server()
