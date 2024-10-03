import hashlib
import time
import random
import string

def generate_random_strings(num_strings, min_length=5, max_length=20):
    """Generate a list of random strings."""
    strings = []
    for _ in range(num_strings):
        length = random.randint(min_length, max_length)
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        strings.append(random_string)
    return strings

def hash_with_md5(data):
    """Compute MD5 hash."""
    return hashlib.md5(data.encode()).hexdigest()

def hash_with_sha1(data):
    """Compute SHA-1 hash."""
    return hashlib.sha1(data.encode()).hexdigest()

def hash_with_sha256(data):
    """Compute SHA-256 hash."""
    return hashlib.sha256(data.encode()).hexdigest()

def measure_hash_time(hash_func, data):
    """Measure the time taken to compute the hash."""
    start_time = time.time()
    hash_value = hash_func(data)
    end_time = time.time()
    return hash_value, end_time - start_time

def find_collisions(hash_dict):
    """Detect any collisions in the hash dictionary."""
    collisions = {}
    for original, hash_value in hash_dict.items():
        if hash_value in collisions:
            collisions[hash_value].append(original)
        else:
            collisions[hash_value] = [original]
    return {k: v for k, v in collisions.items() if len(v) > 1}

def main():
    num_strings = 100  # Number of random strings to generate
    random_strings = generate_random_strings(num_strings)

    # Initialize dictionaries to store hash values and computation times
    md5_hashes = {}
    sha1_hashes = {}
    sha256_hashes = {}
    
    # Hashing with MD5
    print("Hashing with MD5...")
    for s in random_strings:
        hash_value, elapsed_time = measure_hash_time(hash_with_md5, s)
        md5_hashes[s] = (hash_value, elapsed_time)
    
    # Hashing with SHA-1
    print("Hashing with SHA-1...")
    for s in random_strings:
        hash_value, elapsed_time = measure_hash_time(hash_with_sha1, s)
        sha1_hashes[s] = (hash_value, elapsed_time)

    # Hashing with SHA-256
    print("Hashing with SHA-256...")
    for s in random_strings:
        hash_value, elapsed_time = measure_hash_time(hash_with_sha256, s)
        sha256_hashes[s] = (hash_value, elapsed_time)

    # Find collisions in each hash technique
    print("\nCollision Detection:")
    md5_collisions = find_collisions({s: hv[0] for s, hv in md5_hashes.items()})
    sha1_collisions = find_collisions({s: hv[0] for s, hv in sha1_hashes.items()})
    sha256_collisions = find_collisions({s: hv[0] for s, hv in sha256_hashes.items()})

    # Output results
    print("\nMD5 Collisions:", md5_collisions)
    print("SHA-1 Collisions:", sha1_collisions)
    print("SHA-256 Collisions:", sha256_collisions)

    # Summary of time taken for each hashing technique
    md5_time = sum(hv[1] for hv in md5_hashes.values())
    sha1_time = sum(hv[1] for hv in sha1_hashes.values())
    sha256_time = sum(hv[1] for hv in sha256_hashes.values())

    print("\nTime taken for hashing:")
    print(f"MD5: {md5_time:.6f} seconds")
    print(f"SHA-1: {sha1_time:.6f} seconds")
    print(f"SHA-256: {sha256_time:.6f} seconds")

if __name__ == "__main__":
    main()
