from __future__ import annotations

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
        self.value = digest(self.salt + to_commit)

    def serialize(self, data: bytes) -> bytes:
        return self.salt + data

    def verify(self, opening: bytes) -> bool:
        return self.value == digest(self.serialize(opening))

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
