"""KeyPair management module for ValtDB."""

from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class KeyPair:
    """A class representing a public/private key pair."""

    def __init__(
        self,
        private_key: Optional[rsa.RSAPrivateKey] = None,
        public_key: Optional[rsa.RSAPublicKey] = None,
    ):
        """Initialize key pair.

        Args:
            private_key: Optional RSA private key
            public_key: Optional RSA public key
        """
        if private_key and not public_key:
            self.private_key = private_key
            self.public_key = private_key.public_key()
        elif public_key and not private_key:
            self.private_key = None
            self.public_key = public_key
        elif private_key and public_key:
            self.private_key = private_key
            self.public_key = public_key
        else:
            # Generate new key pair
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.public_key = self.private_key.public_key()

    @property
    def has_private_key(self) -> bool:
        """Check if private key is available."""
        return self.private_key is not None

    def serialize(self) -> Tuple[bytes, bytes]:
        """Serialize key pair to bytes."""
        if not self.private_key:
            raise ValueError("Cannot serialize without private key")

        private_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return private_bytes, public_bytes

    @classmethod
    def deserialize(
        cls, private_bytes: Optional[bytes] = None, public_bytes: Optional[bytes] = None
    ) -> "KeyPair":
        """Create key pair from serialized bytes."""
        private_key = None
        public_key = None

        if private_bytes:
            private_key = serialization.load_pem_private_key(private_bytes, password=None)

        if public_bytes:
            public_key = serialization.load_pem_public_key(public_bytes)

        return cls(private_key, public_key)

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data using public key."""
        return self.public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
            ),
        )

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using private key."""
        if not self.private_key:
            raise ValueError("Cannot decrypt without private key")

        return self.private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
            ),
        )
