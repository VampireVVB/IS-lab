def hash_function(input_string):
    # Initial hash value
    hash_value = 5381

    # Iterate through each character in the input string
    for char in input_string:
        # Multiply current hash by 33 and add ASCII value of the character
        hash_value = ((hash_value << 5) + hash_value) + ord(char)  # Equivalent to hash_value * 33 + ord(char)
        
        # Ensure the hash value is within a 32-bit range
        hash_value &= 0xFFFFFFFF  # Apply a mask to keep it within 32 bits

    return hash_value

# Example usage
input_string = "Hello, World!"
hash_value = hash_function(input_string)
print(f"Hash value for '{input_string}': {hash_value}")
