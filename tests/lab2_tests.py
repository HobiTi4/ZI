import unittest
from labs.lab2 import MD5


class TestLab2MD5(unittest.TestCase):

    def setUp(self):
        self.rfc_1321_tests = {
            "": "d41d8cd98f00b204e9800998ecf8427e",
            "a": "0cc175b9c0f1b6a831c399e269772661",
            "abc": "900150983cd24fb0d6963f7d28e17f72",
            "message digest": "f96b697d7cb7938d525a2f31aaf161d0",
            "abcdefghijklmnopqrstuvwxyz": "c3fcd3d76192e4007dfb496cca67e13b",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789": "d174ab98d277d9f5a5611c2c9f419d9f",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890": "57edf4a22be3c955ac49da2e2107b67a"
        }

    def test_rfc1321_cases(self):
        for input_string, expected_hash in self.rfc_1321_tests.items():
            with self.subTest(input_string=input_string):
                hasher = MD5()
                calculated_hash = hasher.hash_string(input_string)
                self.assertEqual(calculated_hash, expected_hash)


if __name__ == "__main__":
    unittest.main()