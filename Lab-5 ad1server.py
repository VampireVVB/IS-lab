import socket
import hashlib

def compute_hash(message):
    """Compute the hash of the given message using SHA-256."""
    return hashlib.sha256(message.encode()).hexdigest()

def start_server(host='127.0.0.1', port=65432):
    """Start the server to receive messages from the client."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f'Server listening on {host}:{port}...')
        
        conn, addr = s.accept()
        with conn:
            print(f'Connected by {addr}')
            message_parts = []

            while True:
                data = conn.recv(1024)
                if not data:
                    break
                message_parts.append(data.decode())
                print(f'Received part: {data.decode()}')

            # Reassemble the message
            full_message = ''.join(message_parts)
            print(f'Reassembled message: {full_message}')

            # Compute the hash of the reassembled message
            message_hash = compute_hash(full_message)
            print(f'Computed hash: {message_hash}')

            # Send the hash back to the client
            conn.sendall(message_hash.encode())
            print('Sent hash to client.')

if __name__ == '__main__':
    start_server()
