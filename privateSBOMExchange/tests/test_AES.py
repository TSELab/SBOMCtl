from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Function to generate a 32-byte AES key (AES-256)
def generate_key():
    # Generate a 32-byte (256-bit) AES key
    return get_random_bytes(32)

# Function to encrypt the plaintext using AES-256 (CBC mode)
def encrypt(plaintext, key):
    # Generate a random 16-byte IV
    iv = get_random_bytes(AES.block_size)
    
    # Pad the plaintext to be a multiple of AES.block_size (16 bytes)
    padding_length = AES.block_size - len(plaintext) % AES.block_size
    plaintext_padded = plaintext + chr(padding_length) * padding_length
    
    # Convert plaintext to bytes
    plaintext_bytes = plaintext_padded.encode('utf-8')
    
    # Create AES cipher object with the key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Encrypt the plaintext
    ciphertext = cipher.encrypt(plaintext_bytes)
    
    # Concatenate the IV and ciphertext
    iv_ciphertext = iv + ciphertext
    
    # Base64 encode the concatenated IV + ciphertext for safe transmission
    iv_ciphertext_base64 = base64.b64encode(iv_ciphertext).decode('utf-8')
    
    return iv_ciphertext_base64

# Function to decrypt the ciphertext using AES-256 (CBC mode)
def decrypt(encrypted_data, key):
    # Base64 decode the concatenated IV + ciphertext
    iv_ciphertext = base64.b64decode(encrypted_data)
    
    # Extract the IV (first 16 bytes) and the ciphertext (rest of the data)
    iv = iv_ciphertext[:AES.block_size]
    ciphertext = iv_ciphertext[AES.block_size:]
    
    # Create AES cipher object with the key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt the ciphertext
    decrypted_padded = cipher.decrypt(ciphertext)
    
    # Remove padding (assuming PKCS7 padding)
    padding_length = decrypted_padded[-1]
    decrypted = decrypted_padded[:-padding_length].decode('utf-8')
    
    return decrypted


# Example usage:
if __name__ == "__main__":
    # Generate a new AES key (32 bytes for AES-256)
    key = generate_key()
    print(f"Generated Key: {key.hex()}")  # Printing key in hex format for better readability

    # Encrypt a message
    plaintext = "This is a secret message."
    encrypted_data = encrypt(plaintext, key)
    print(f"Encrypted Data (Base64): {encrypted_data}")

    # Decrypt the message
    decrypted_message = decrypt(encrypted_data, key)
    print(f"Decrypted Message: {decrypted_message}")
