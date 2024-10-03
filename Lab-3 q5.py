import os
import time
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def generate_dh_parameters():
    """Generate Diffie-Hellman parameters."""
    return dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

def generate_keys(parameters):
    """Generate public and private keys for a peer."""
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def compute_shared_secret(private_key, peer_public_key):
    """Compute the shared secret using the private key and peer's public key."""
    return private_key.exchange(peer_public_key)

def measure_diffie_hellman():
    """Measure the time taken for key generation and key exchange processes."""
    # Generate Diffie-Hellman parameters
    start_time = time.time()
    parameters = generate_dh_parameters()
    param_generation_time = time.time() - start_time
    
    # Generate keys for Peer A
    start_time = time.time()
    peer_a_private_key, peer_a_public_key = generate_keys(parameters)
    peer_a_key_generation_time = time.time() - start_time

    # Generate keys for Peer B
    start_time = time.time()
    peer_b_private_key, peer_b_public_key = generate_keys(parameters)
    peer_b_key_generation_time = time.time() - start_time

    # Compute shared secret for Peer A
    start_time = time.time()
    peer_a_shared_secret = compute_shared_secret(peer_a_private_key, peer_b_public_key)
    peer_a_shared_secret_time = time.time() - start_time

    # Compute shared secret for Peer B
    start_time = time.time()
    peer_b_shared_secret = compute_shared_secret(peer_b_private_key, peer_a_public_key)
    peer_b_shared_secret_time = time.time() - start_time

    print(f'Diffie-Hellman Parameter Generation Time: {param_generation_time:.6f} seconds')
    print(f'Peer A Key Generation Time: {peer_a_key_generation_time:.6f} seconds')
    print(f'Peer B Key Generation Time: {peer_b_key_generation_time:.6f} seconds')
    print(f'Peer A Shared Secret Computation Time: {peer_a_shared_secret_time:.6f} seconds')
    print(f'Peer B Shared Secret Computation Time: {peer_b_shared_secret_time:.6f} seconds')

    # Verify that both peers computed the same shared secret
    assert peer_a_shared_secret == peer_b_shared_secret, "Shared secrets do not match!"
    print(f'Shared secret (hex): {peer_a_shared_secret.hex()}')

if __name__ == "__main__":
    measure_diffie_hellman()
