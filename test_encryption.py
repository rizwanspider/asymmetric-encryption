import unittest
from unittest import TestCase
import re
from encryption import AsymmetricEncryption

#-------------------------------------------------------------------------------
# TestAsymmetricEncryption
#-------------------------------------------------------------------------------
class TestAsymmetricEncryption(TestCase):

    def setUp(self):
        self.crypto = AsymmetricEncryption()
        self.private_key = self.crypto.generate_rsa_keypair()
        self.public_key = self.private_key.public_key()
        
    def tearDown(self):
        pass

    def test_encrypt(self):
        password = b'myStrongPassword'

        cipher_pass = self.crypto.encrypt(
            self.public_key, password
        )
        self.assertEqual(type(cipher_pass), bytes)

    def test_decrypt(self):
        message = b'encrypted data'

        cipher_pass = self.crypto.encrypt(
            self.public_key, message
        )

        plaintext = self.crypto.decrypt(
            self.private_key, cipher_pass
        )
        self.assertEqual(plaintext, message)

if __name__ == '__main__':
    unittest.main()