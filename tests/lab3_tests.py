import unittest
import os
from labs.lab3 import RC5, derive_key, rc5_cbc_pad_encrypt, rc5_cbc_pad_decrypt


class TestLab3RC5(unittest.TestCase):

    def setUp(self):
        self.w = 16
        self.r = 8
        self.b = 16
        self.password = "31fdsFDSKL12DSdffy7sq433eif21FsdkhjDS"
        self.key = derive_key(self.password, self.b)
        self.rc5 = RC5(self.w, self.r, self.key)

    def test_bitwise_rotations(self):
        val = 0x1234

        self.assertEqual(self.rc5._rotate_left(val, 4), 0x2341)

        self.assertEqual(self.rc5._rotate_right(val, 4), 0x4123)

    def test_block_encryption_decryption(self):
        A_orig = 0xABCD
        B_orig = 0x1234

        enc_A, enc_B = self.rc5.encrypt_block(A_orig, B_orig)

        dec_A, dec_B = self.rc5.decrypt_block(enc_A, enc_B)

        self.assertEqual(A_orig, dec_A)
        self.assertEqual(B_orig, dec_B)

    def test_file_encryption_decryption_cbc_pad(self):
        test_input = "test_input.txt"
        test_enc = "test_input.enc"
        test_dec = "test_input_dec.txt"

        original_data = b"Hello! This is a test string for RC5-CBC-Pad algorithm."

        with open(test_input, "wb") as f:
            f.write(original_data)

        rc5_cbc_pad_encrypt(test_input, test_enc, self.password, self.w, self.r, self.b)
        self.assertTrue(os.path.exists(test_enc))

        rc5_cbc_pad_decrypt(test_enc, test_dec, self.password, self.w, self.r, self.b)

        with open(test_dec, "rb") as f:
            decrypted_data = f.read()

        self.assertEqual(original_data, decrypted_data)

        os.remove(test_input)
        os.remove(test_enc)
        os.remove(test_dec)

    def test_wrong_password_raises_error(self):
        test_input = "test_wrong_pass.txt"
        test_enc = "test_wrong_pass.enc"
        test_dec = "test_wrong_pass_dec.txt"

        with open(test_input, "wb") as f:
            f.write(b"Confidential data.")

        rc5_cbc_pad_encrypt(test_input, test_enc, self.password, self.w, self.r, self.b)

        with self.assertRaises(ValueError):
            rc5_cbc_pad_decrypt(test_enc, test_dec, "wrong_password_123", self.w, self.r, self.b)

        os.remove(test_input)
        os.remove(test_enc)
        if os.path.exists(test_dec):
            os.remove(test_dec)