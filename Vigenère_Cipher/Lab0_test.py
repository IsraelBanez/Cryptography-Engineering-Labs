import unittest
from Lab0 import *


class Test(unittest.TestCase):

    # Test case for | A. Implement Encoders & Decoders
    def test_ascii_hex(self):
        self.assertEqual(ascii_str_to_hex(b"Hello World"),
                         b'48656c6c6f20576f726c64', "Error: test_ascii_hex")

    def test_hex_ascii(self):
        self.assertEqual(hex_to_ascii(b'48656c6c6f20576f726c64'),
                         b"Hello World", "Error: test_hex_ascii")

    def test_base64_hex(self):
        self.assertEqual(base64_str_to_hex(b'SGVsbG8gV29ybGQ='),
                         b'48656c6c6f20576f726c64', "Error: test_base64_hex")

    def test_hex_base64(self):
        self.assertEqual(hex_to_base64(b'48656c6c6f20576f726c64'),
                         b'SGVsbG8gV29ybGQ=', "Error: test_hex_base64")

    # Test case for | Part A: Implement XOR

    def test_xor_bytes(self):
        self.assertEqual(xor_two_bstr(b'what', b'hey'),
                         b'\x1f\r\x18\x1c', "Error: test_xor_bytes ")


if __name__ == '__main__':
    unittest.main()
