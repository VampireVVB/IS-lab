import socket
import hashlib

def compute_hash(message):
    """Compute the hash of the given message using SHA-256."""
    return hashlib.sha256(message.encode()).hexdigest()

def send_message_in_parts(message, host='127.0.0.1', port=65432):
    """Send the message in parts to the server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print(f'Connected to server at {host}:{port}')
        
        # Send the message in parts
        parts = [message[i:i + 10] for i in range(0, len(message), 10)]  # Sending in chunks of 10
        for part in parts:
            s.sendall(part.encode())
            print(f'Sent part: {part}')
        
        # Signal that we are done sending
        s.sendall(b'')
        
        # Receive the hash from the server
        received_hash = s.recv(1024).decode()
        print(f'Received hash from server: {received_hash}')

    # Verify the integrity of the message
    computed_hash = compute_hash(message)
    print(f'Computed hash of original message: {computed_hash}')

    if computed_hash == received_hash:
        print('Integrity verified: Hashes match.')
    else:
        print('Integrity check failed: Hashes do not match.')

if __name__ == '__main__':
    message = "This is a test message that will be sent in multiple parts."
    send_message_in_parts(message)
