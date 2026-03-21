import unittest
import os
from labs.lab4 import generate_rsa_keys, rsa_encrypt_data, rsa_decrypt_data


class TestLab4RSA(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.priv_pem, cls.pub_pem = generate_rsa_keys(key_size=2048)

    def test_key_generation(self):
        priv, pub = generate_rsa_keys(key_size=1024)

        self.assertIn(b"BEGIN PRIVATE KEY", priv)
        self.assertIn(b"BEGIN PUBLIC KEY", pub)

    def test_encrypt_decrypt_small_data(self):
        original_data = b"Testing text classification pipeline data"

        encrypted = rsa_encrypt_data(original_data, self.pub_pem)
        self.assertNotEqual(original_data, encrypted)

        decrypted = rsa_decrypt_data(encrypted, self.priv_pem)
        self.assertEqual(original_data, decrypted)

    def test_encrypt_decrypt_large_data(self):
        original_data = os.urandom(5000)

        encrypted = rsa_encrypt_data(original_data, self.pub_pem)
        self.assertTrue(len(encrypted) > len(original_data))
        decrypted = rsa_decrypt_data(encrypted, self.priv_pem)
        self.assertEqual(original_data, decrypted)

    def test_tampered_data_fails(self):
        original_data = b"Sensitive configuration data"
        encrypted = bytearray(rsa_encrypt_data(original_data, self.pub_pem))

        encrypted[10] = encrypted[10] ^ 0xFF

        with self.assertRaises(ValueError):
            rsa_decrypt_data(bytes(encrypted), self.priv_pem)


if __name__ == '__main__':
    unittest.main()