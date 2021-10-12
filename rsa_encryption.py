from cryptography.hazmat.primitives.asymmetric.rsa import (
    generate_private_key,
    RSAPublicKey,
    RSAPrivateKey,
)
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

#-------------------------------------------------------------------------------
# RSAEncryption
#-------------------------------------------------------------------------------
class RSAEncryption():
    """RSA is a public-key algorithm for encrypting and signing messages."""
    
    def generate_rsa_keypair(self, bits=2048):
        return generate_private_key(
            public_exponent=65537,
            key_size=bits,
            backend=default_backend()
        )

    def load_private_key(self, pem_file_path):
        with open(pem_file_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        return private_key

    def load_public_key(self, pem_file_path):
        with open(pem_file_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        return public_key

    def encrypt(self, public_key, message):
        """
        Encryption using a secure padding and hash function.
        """
        return public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt(self, private_key, cipher_pass):
        """
        Once you have an encrypted message, it can be decrypted using the private key.
        """
        return private_key.decrypt(
            cipher_pass,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
