"""
Keypair management for ValtDB.

This module provides functionality for managing cryptographic key pairs,
with a focus on RSA key types for secure encryption and decryption.
"""

import base64
from typing import Tuple, Union, cast

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)
from cryptography.hazmat.primitives.hashes import SHA256


class KeyPair:
    """
    A class representing a cryptographic key pair with RSA keys.

    Attributes:
        private_key (rsa.RSAPrivateKey): The private key of the key pair.
        public_key (rsa.RSAPublicKey): The public key of the key pair.
    """

    def __init__(
        self,
        private_key: Union[rsa.RSAPrivateKey, PrivateKeyTypes],
        public_key: Union[rsa.RSAPublicKey, PublicKeyTypes],
    ):
        """
        Initialize a KeyPair with private and public keys.

        Args:
            private_key (Union[rsa.RSAPrivateKey, PrivateKeyTypes]): The private key to use.
            public_key (Union[rsa.RSAPublicKey, PublicKeyTypes]): The public key to use.

        Raises:
            TypeError: If the provided keys are not of type RSAPrivateKey or RSAPublicKey.
        """
        # Validate private key type
        if not isinstance(private_key, rsa.RSAPrivateKey):
            try:
                private_key = cast(rsa.RSAPrivateKey, private_key)
            except Exception:
                raise TypeError(f"Private key must be an RSAPrivateKey, got {type(private_key)}")

        # Validate public key type
        if not isinstance(public_key, rsa.RSAPublicKey):
            try:
                public_key = cast(rsa.RSAPublicKey, public_key)
            except Exception:
                raise TypeError(f"Public key must be an RSAPublicKey, got {type(public_key)}")

        self.private_key: rsa.RSAPrivateKey = private_key
        self.public_key: rsa.RSAPublicKey = public_key

    def serialize(self) -> Tuple[bytes, bytes]:
        """
        Serialize the key pair to PEM format.

        Returns:
            Tuple[bytes, bytes]: A tuple containing:
                - Private key bytes
                - Public key bytes
        """
        # Serialize private key
        private_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Serialize public key
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_bytes, public_bytes

    @classmethod
    def deserialize(
        cls, 
        private_bytes: bytes, 
        public_bytes: bytes
    ) -> 'KeyPair':
        """
        Deserialize key pair from PEM format.

        Args:
            private_bytes (bytes): Private key bytes in PEM format.
            public_bytes (bytes): Public key bytes in PEM format.

        Returns:
            KeyPair: A new KeyPair instance with deserialized keys.

        Raises:
            InvalidKey: If the key bytes are invalid.
        """
        # Deserialize private key
        private_key = serialization.load_pem_private_key(
            private_bytes,
            password=None
        )
        # Ensure it's an RSA private key
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise TypeError("Deserialized private key must be an RSAPrivateKey")

        # Deserialize public key
        public_key = serialization.load_pem_public_key(public_bytes)
        # Ensure it's an RSA public key
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise TypeError("Deserialized public key must be an RSAPublicKey")

        return cls(private_key, public_key)

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt data using the public key.

        Args:
            data (bytes): Data to encrypt.

        Returns:
            bytes: Encrypted data.
        """
        return self.public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None
            )
        )

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt data using the private key.

        Args:
            encrypted_data (bytes): Data to decrypt.

        Returns:
            bytes: Decrypted data.
        """
        return self.private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None
            )
        )

    def __repr__(self) -> str:
        """
        String representation of the KeyPair.

        Returns:
            str: A string describing the key pair's state.
        """
        return (
            f"KeyPair(private_key=rsa.RSAPrivateKey, "
            f"public_key=rsa.RSAPublicKey)"
        )
