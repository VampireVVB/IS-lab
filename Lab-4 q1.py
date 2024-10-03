import os
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

class SecureCorpCommunicationSystem:
    def __init__(self):
        self.subsystems = {}
    
    def add_subsystem(self, name):
        """Add a new subsystem with its RSA key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        self.subsystems[name] = {
            'private_key': private_key,
            'public_key': public_key,
            'shared_secret': None
        }
        print(f"Subsystem '{name}' added with RSA key pair.")
    
    def generate_dh_keys(self, name):
        """Generate Diffie-Hellman key pair for the specified subsystem."""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        self.subsystems[name]['dh_private_key'] = private_key
        self.subsystems[name]['dh_public_key'] = public_key
        print(f"DH keys generated for subsystem '{name}'.")

    def compute_shared_secret(self, sender_name, receiver_name):
        """Compute the shared secret using Diffie-Hellman."""
        sender_dh_private_key = self.subsystems[sender_name]['dh_private_key']
        receiver_dh_public_key = self.subsystems[receiver_name]['dh_public_key']
        
        shared_secret = sender_dh_private_key.exchange(ec.ECDH(), receiver_dh_public_key)
        self.subsystems[sender_name]['shared_secret'] = shared_secret
        self.subsystems[receiver_name]['shared_secret'] = shared_secret
        
        print(f"Shared secret computed between '{sender_name}' and '{receiver_name}'.")

    def encrypt_message(self, sender_name, receiver_name, message):
        """Encrypt a message using RSA and the shared secret."""
        sender_public_key = self.subsystems[sender_name]['public_key']
        shared_secret = self.subsystems[sender_name]['shared_secret']
        
        # Encrypt message with sender's public key
        ciphertext = sender_public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Message encrypted from '{sender_name}' to '{receiver_name}'.")
        return ciphertext

    def decrypt_message(self, receiver_name, ciphertext):
        """Decrypt a message using RSA."""
        receiver_private_key = self.subsystems[receiver_name]['private_key']
        
        plaintext = receiver_private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Message decrypted for subsystem '{receiver_name}'.")
        return plaintext.decode()

    def simulate_communication(self, sender_name, receiver_name, message):
        """Simulate secure communication between two subsystems."""
        print(f"\n--- Communication from '{sender_name}' to '{receiver_name}' ---")
        
        # Encrypt the message
        ciphertext = self.encrypt_message(sender_name, receiver_name, message)
        
        # Decrypt the message
        decrypted_message = self.decrypt_message(receiver_name, ciphertext)
        
        print(f"Original Message: {message}")
        print(f"Decrypted Message: {decrypted_message}")

def main():
    # Initialize the communication system
    comms_system = SecureCorpCommunicationSystem()

    # Add subsystems
    comms_system.add_subsystem('Finance System (System A)')
    comms_system.add_subsystem('HR System (System B)')
    comms_system.add_subsystem('Supply Chain Management (System C)')

    # Generate Diffie-Hellman keys for each subsystem
    for subsystem in comms_system.subsystems.keys():
        comms_system.generate_dh_keys(subsystem)

    # Compute shared secrets
    comms_system.compute_shared_secret('Finance System (System A)', 'HR System (System B)')
    comms_system.compute_shared_secret('HR System (System B)', 'Supply Chain Management (System C)')
    
    # Simulate communication
    comms_system.simulate_communication('Finance System (System A)', 'HR System (System B)', 'Financial Report Q1 2024')
    comms_system.simulate_communication('HR System (System B)', 'Supply Chain Management (System C)', 'Employee Contracts for Review')

if __name__ == "__main__":
    main()
