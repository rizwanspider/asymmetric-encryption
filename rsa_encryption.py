import os
from cryptography.hazmat.primitives.asymmetric.rsa import (
    generate_private_key,
    RSAPublicKey,
    RSAPrivateKey,
)
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from utils.file_io import write_bytes

#-------------------------------------------------------------------------------
# RSAEncryption
#-------------------------------------------------------------------------------
class RSAEncryption():
    """RSA is a asymmetric algorithm for encrypting and signing messages."""
    
    #---------------------------------------------------------------------------
    # generate_rsa_keypair
    #---------------------------------------------------------------------------
    def generate_rsa_keypair(self, bits=2048):
        """
        Returns private_key and public_key

        Generates a new RSA private key using the provided backend and key_size.
        """
        private_key = generate_private_key(
            public_exponent=65537,
            key_size=bits,
            backend=default_backend()
        )

        return private_key, private_key.public_key()

    #---------------------------------------------------------------------------
    # write_keys
    #---------------------------------------------------------------------------
    def write_keys(self, private_key, public_key, path):
        self.path = path
        self.write_private_key(private_key)
        self.write_public_key(public_key)

    #---------------------------------------------------------------------------
    # serialize_private_key
    #---------------------------------------------------------------------------
    def serialize_private_key(self, private_key):
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    #---------------------------------------------------------------------------
    # serialize_public_key
    #---------------------------------------------------------------------------
    def serialize_public_key(self, public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    #---------------------------------------------------------------------------
    # write_private_key
    #---------------------------------------------------------------------------
    def write_private_key(self, private_key):
        filename = 'private_noshare.pem'
        path = os.path.join(self.path, filename)
        serial_private = self.serialize_private_key(private_key)
        write_bytes(serial_private, path)
    
    #---------------------------------------------------------------------------
    # write_public_key
    #---------------------------------------------------------------------------
    def write_public_key(self, public_key):
        filename = 'public_shared.pem'
        path = os.path.join(self.path, filename)
        serial_pub = self.serialize_public_key(public_key)
        write_bytes(serial_pub, path)

    #---------------------------------------------------------------------------
    # load_private_key
    #---------------------------------------------------------------------------
    def load_private_key(self, pem_file_path):
        """
        If you already have an on-disk key in the PEM format.
        """
        with open(pem_file_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        return private_key

    #---------------------------------------------------------------------------
    # load_public_key
    #---------------------------------------------------------------------------
    def load_public_key(self, pem_file_path):
        """
        If you already have an on-disk key in the PEM format.
        """
        with open(pem_file_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        return public_key

    #---------------------------------------------------------------------------
    # get_encrypt
    #---------------------------------------------------------------------------
    def get_encrypt(self, public_key, message):
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

    #---------------------------------------------------------------------------
    # get_decrypt
    #---------------------------------------------------------------------------
    def get_decrypt(self, private_key, cipher_pass):
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
