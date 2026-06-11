import unittest


from petra.crypto import generate_AES_key, encrypt_data_AES, decrypt_data_AES


class TestAES(unittest.TestCase):
    def test_example_usage(self):
        # Generate a new AES key (32 bytes for AES-256)
        key = generate_AES_key()

        # Encrypt a message
        plaintext = "This is a secret message."
        encrypted_data = encrypt_data_AES(plaintext.encode(), key)

        # Decrypt the message
        decrypted_message = decrypt_data_AES(encrypted_data, key)
        self.assertEqual(plaintext, decrypted_message.decode())
