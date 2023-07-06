import unittest
from lab2 import *

class Test(unittest.TestCase):

    def test_pkcs7_pad(self):
        self.assertEqual(pkcs7_pad(b"+Ofgd5nCk9IEHy12lr2e5tTn7QAE" , 16),
                         b'+Ofgd5nCk9IEHy12lr2e5tTn7QAE\x04\x04\x04\x04', "Error: test_pkcs7_pad")

    def test_pkcs7_unpad(self):
        self.assertEqual(pkcs7_unpad(b'+Ofgd5nCk9IEHy12lr2e5tTn7QAE\x04\x04\x04\x04' , 16),
                         b'+Ofgd5nCk9IEHy12lr2e5tTn7QAE', "Error: test_pkcs7_unpad")
    
    def test_pkcs7_unpad_error(self):
        self.assertRaises(ValueError, pkcs7_unpad, b"+Ofgd5nCk9IEHy12lr2e5tTn7QAE", 16)
    

if __name__ == '__main__':
    unittest.main()