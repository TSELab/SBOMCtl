from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

from petra.crypto import generate_AES_key, encrypt_data_AES,decrypt_data_AES

# Example usage:
if __name__ == "__main__":
    # Generate a new AES key (32 bytes for AES-256)
    key = generate_AES_key()
    print(f"Generated Key: {key.hex()}")  # Printing key in hex format for better readability

    # Encrypt a message
    plaintext = "This is a secret message."
    encrypted_data = encrypt_data_AES(plaintext.encode(), key)
    print(f"Encrypted Data (Base64): {encrypted_data}")

    # Decrypt the message
    decrypted_message = decrypt_data_AES(encrypted_data, key)
    print(f"Decrypted Message: {decrypted_message}")
