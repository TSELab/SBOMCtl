from __future__ import annotations
import hashlib
import sys
import os

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

import secrets
import hashlib

DEFAULT_HASH_SIZE_BYTES=32 # 256 bit

def digest(to_hash:bytes) -> bytes:
        return hashlib.sha256(to_hash).digest()

def get_salt() -> bytes:
    rand = secrets.token_bytes(DEFAULT_HASH_SIZE_BYTES)

    # we hash it as an extra measure to "hide" the random nonce
    return digest(rand)

class Commitment:
    """ Implements a simple cryptographic commitment."""
    def __init__(self, to_commit: bytes) -> None:
        self.salt = get_salt()
        self.value = digest(self.serialize(to_commit))

    def serialize(self, data: bytes) -> bytes:
        return self.salt + data

    def verify(self, salt: bytes, opening: bytes) -> bool:
        return self.value == digest(salt + opening)

    def to_hex(self) -> (str, str):
        return self.salt.hex(), self.value.hex()

    @staticmethod
    def from_hex(hex_commit: tuple) -> Commitment:
        c = Commitment(b'0x00') # we need to override this dummy commit
        c.salt = bytes.fromhex(hex_commit[0])
        c.value = bytes.fromhex(hex_commit[1])

        return c

'''
try:
    from cpabe import cpabe_decrypt, cpabe_encrypt, cpabe_keygen, cpabe_setup, cpabe_delegate
except:
    print("Can't import cpabe! Make sure you ran maturing develop or installed the cpabe package under src!")

def init_abe():
    return cpabe_setup()

def decrypt_SBOM_field(bundle, field_name, secret_key):
    for key, value in bundle:
        if key == field_name:
            target = value
            break
        print(key)
    else:
        return None
    result_array = cpabe_decrypt(secret_key, target)
    return "".join([chr(x) for x in result_array])

def generate_user_private_key(public_key, master_key, user_attributes):
    return cpabe_keygen(public_key, master_key, user_attributes)

def encrypt_SBOM(flatten_SBOM_data, pub_key, policy):

    result = []
    for key, value in flatten_SBOM_data.items():
        if isinstance(value, bool):
            value=str(value)
        ct = cpabe_encrypt(pub_key, policy, value.encode("utf-8"))
        result.append((key, ct))
    return result
'''


def generate_AES_key():
    # Generate a 32-byte (256-bit) AES key
    return get_random_bytes(32)


# Function to encrypt the plaintext using AES-256 (CBC mode)
def encrypt_data_AES(plaintext, key):
    # Generate a random 16-byte IV
    iv = get_random_bytes(AES.block_size)
    
    # Pad the plaintext to be a multiple of AES.block_size (16 bytes)
    padding_length = AES.block_size - len(plaintext) % AES.block_size

    padding = bytes([padding_length] * padding_length)
    plaintext_padded = plaintext + padding

    # Create AES cipher object with the key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Encrypt the plaintext
    ciphertext = cipher.encrypt(plaintext_padded)
    
    # Concatenate the IV and ciphertext
    iv_ciphertext = iv + ciphertext
    
    # Base64 encode the concatenated IV + ciphertext for safe transmission
    iv_ciphertext_base64 = base64.b64encode(iv_ciphertext).decode('utf-8')
    
    return iv_ciphertext_base64


# Function to decrypt the ciphertext using AES-256 (CBC mode)
def decrypt_data_AES(ciphertext_base64, key):
    # Ensure the key is 16 bytes long (128-bit AES)
    if len(key) != 32:
        raise ValueError("Key must be 16 bytes long")
    
    # Base64 decode the concatenated IV + ciphertext
    iv_ciphertext = base64.b64decode(ciphertext_base64)
    
    # Extract the IV (first 16 bytes)
    iv = iv_ciphertext[:AES.block_size]
    
    # Extract the ciphertext (remaining bytes)
    ciphertext = iv_ciphertext[AES.block_size:]
    
    # Create AES cipher object with the key and IV (CBC mode)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt the ciphertext
    decrypted_padded = cipher.decrypt(ciphertext)
    
    # The padding is the value of the last byte, so we remove it
    padding_length = decrypted_padded[-1]
    
    # Check if padding_length is valid (should not be larger than block size)
    if padding_length > AES.block_size:
        raise ValueError("Invalid padding length.")
    
    # Remove the padding
    plaintext_bytes = decrypted_padded[:-padding_length]
    
    return plaintext_bytes