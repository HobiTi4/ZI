import unittest
from labs.lab5 import generate_dsa_keys, dsa_sign, dsa_verify


class TestLab5DSA(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.priv_pem, cls.pub_pem = generate_dsa_keys(key_size=2048)

    def test_key_generation(self):
        priv, pub = generate_dsa_keys(key_size=1024)
        self.assertIn(b"BEGIN PRIVATE KEY", priv)
        self.assertIn(b"BEGIN PUBLIC KEY", pub)

    def test_sign_and_verify_success(self):
        data = b"Important financial document data"

        signature_hex = dsa_sign(data, self.priv_pem)
        self.assertTrue(len(signature_hex) > 0)

        is_valid = dsa_verify(data, signature_hex, self.pub_pem)
        self.assertTrue(is_valid)

    def test_verify_fails_on_tampered_data(self):
        original_data = b"Transfer $100 to account A"
        tampered_data = b"Transfer $900 to account A"

        signature_hex = dsa_sign(original_data, self.priv_pem)

        is_valid = dsa_verify(tampered_data, signature_hex, self.pub_pem)
        self.assertFalse(is_valid)

    def test_verify_fails_on_tampered_signature(self):
        data = b"Firmware update package"
        signature_hex = dsa_sign(data, self.priv_pem)

        tampered_sig = "0" + signature_hex[1:] if signature_hex[0] != "0" else "1" + signature_hex[1:]

        is_valid = dsa_verify(data, tampered_sig, self.pub_pem)
        self.assertFalse(is_valid)


if __name__ == '__main__':
    unittest.main()