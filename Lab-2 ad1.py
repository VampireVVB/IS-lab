import time
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import matplotlib.pyplot as plt

# Define messages
messages = [
    "This is the first secret message.",
    "Here's the second confidential message.",
    "Third message for encryption testing.",
    "Fourth message goes here!",
    "Last but not least, the fifth message."
]

# Define keys (make sure they are valid lengths)
des_key = b'12345678'  # 8 bytes for DES
aes_key_128 = b'0123456789ABCDEF'  # 16 bytes for AES-128
aes_key_192 = b'0123456789ABCDEFFEDCBA9876543210'  # 24 bytes for AES-192
aes_key_256 = b'0123456789ABCDEFFEDCBA9876543210ABCDEF'  # 32 bytes for AES-256

# Define modes of operation
modes = {
    "DES ECB": DES.MODE_ECB,
    "DES CBC": DES.MODE_CBC,
    "AES-128 ECB": AES.MODE_ECB,
    "AES-128 CBC": AES.MODE_CBC,
    "AES-192 ECB": AES.MODE_ECB,
    "AES-192 CBC": AES.MODE_CBC,
    "AES-256 ECB": AES.MODE_ECB,
    "AES-256 CBC": AES.MODE_CBC,
}

# Store execution times
execution_times = {key: [] for key in modes.keys()}

# Function to encrypt messages
def encrypt_message(cipher, message):
    iv = b'\x00' * 16  # Initialization vector for CBC mode (zeroed for simplicity)
    if cipher == DES:
        cipher_obj = cipher.new(des_key, modes[cipher])
    else:
        cipher_obj = cipher.new(aes_key_128 if '128' in cipher else aes_key_192 if '192' in cipher else aes_key_256, modes[cipher], iv)
    
    start_time = time.time()
    if 'CBC' in cipher:
        ciphertext = cipher_obj.encrypt(pad(message.encode(), AES.block_size))
    else:
        ciphertext = cipher_obj.encrypt(pad(message.encode(), DES.block_size))
    execution_time = time.time() - start_time
    return execution_time

# Encrypt messages and measure execution times
for message in messages:
    for mode, mode_type in modes.items():
        if "DES" in mode:
            cipher = DES
        else:
            cipher = AES
        
        exec_time = encrypt_message(cipher, message)
        execution_times[mode].append(exec_time)

# Plotting results
labels = list(execution_times.keys())
times = [execution_times[label] for label in labels]

# Prepare data for plotting
x = range(len(messages))

plt.figure(figsize=(12, 6))
for i, mode in enumerate(labels):
    plt.plot(x, times[i], marker='o', label=mode)

plt.xticks(x, [f'Message {i+1}' for i in range(len(messages))])
plt.xlabel('Messages')
plt.ylabel('Execution Time (seconds)')
plt.title('Execution Time for Encryption in Different Modes of Operation')
plt.legend()
plt.grid()
plt.show()
