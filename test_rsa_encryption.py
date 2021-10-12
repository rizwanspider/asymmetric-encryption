import unittest
from unittest import TestCase
import re
from rsa_encryption import RSAEncryption

#-------------------------------------------------------------------------------
# TestRSAEncryption
#-------------------------------------------------------------------------------
class TestRSAEncryption(TestCase):

    def setUp(self):
        self.crypto = RSAEncryption()
        self.private_key, self.public_key = self.crypto.generate_rsa_keypair()
        
    def tearDown(self):
        pass

    def test_encrypt(self):
        password = b'myStrongPassword'

        cipher_pass = self.crypto.get_encrypt(
            self.public_key, password
        )
        self.assertEqual(type(cipher_pass), bytes)

    def test_decrypt(self):
        message = b'encrypted data'

        cipher_pass = self.crypto.get_encrypt(
            self.public_key, message
        )

        plaintext = self.crypto.get_decrypt(
            self.private_key, cipher_pass
        )
        self.assertEqual(plaintext, message)

if __name__ == '__main__':
    unittest.main()