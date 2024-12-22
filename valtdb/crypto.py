"""Encryption and key management for ValtDB."""

from typing import Optional, Any, Dict, Union
from cryptography.fernet import Fernet
import base64
import json
import os

from .exceptions import ValtDBError

class KeyPair:
    """Represents a public/private key pair."""
    def __init__(self, public_key: bytes, private_key: Optional[bytes] = None):
        self.public_key = public_key
        self.private_key = private_key

    @classmethod
    def generate(cls) -> 'KeyPair':
        """Generate a new key pair."""
        key = Fernet.generate_key()
        return cls(public_key=key, private_key=key)

    @classmethod
    def from_password(cls, password: str) -> 'KeyPair':
        """Create a key pair from a password."""
        if not password:
            raise ValtDBError("Password cannot be empty")
        key = base64.urlsafe_b64encode(password.encode().ljust(32)[:32])
        return cls(public_key=key, private_key=key)

    def to_dict(self) -> Dict[str, str]:
        """Convert key pair to dictionary."""
        return {
            "public_key": base64.b64encode(self.public_key).decode(),
            "private_key": base64.b64encode(self.private_key).decode() if self.private_key else None
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'KeyPair':
        """Create key pair from dictionary."""
        return cls(
            public_key=base64.b64decode(data["public_key"]),
            private_key=base64.b64decode(data["private_key"]) if data.get("private_key") else None
        )

class EncryptionManager:
    """Manages encryption operations."""
    def __init__(self, password: Optional[str] = None):
        """Initialize encryption manager with optional password."""
        self.keypair = KeyPair.from_password(password) if password else None
        self.fernet = Fernet(self.keypair.public_key) if self.keypair else None

    @classmethod
    def from_password(cls, password: str) -> 'EncryptionManager':
        """Create encryption manager from password."""
        return cls(password=password)

    def encrypt_data(self, data: Union[str, bytes, Dict[str, Any]]) -> bytes:
        """Encrypt data."""
        if not self.fernet:
            raise ValtDBError("Encryption not initialized")

        if isinstance(data, str):
            data_bytes = data.encode()
        elif isinstance(data, dict):
            data_bytes = json.dumps(data).encode()
        else:
            data_bytes = data

        return self.fernet.encrypt(data_bytes)

    def decrypt_data(self, encrypted_data: bytes) -> Union[str, Dict[str, Any]]:
        """Decrypt data."""
        if not self.fernet:
            raise ValtDBError("Encryption not initialized")

        decrypted = self.fernet.decrypt(encrypted_data)
        
        try:
            # Try to decode as JSON
            return json.loads(decrypted.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            # If not JSON, return as string
            return decrypted.decode()

    def encrypt_file(self, file_path: str) -> None:
        """Encrypt a file in place."""
        if not self.fernet:
            raise ValtDBError("Encryption not initialized")

        with open(file_path, 'rb') as f:
            data = f.read()

        encrypted_data = self.encrypt_data(data)

        with open(file_path, 'wb') as f:
            f.write(encrypted_data)

    def decrypt_file(self, file_path: str) -> None:
        """Decrypt a file in place."""
        if not self.fernet:
            raise ValtDBError("Encryption not initialized")

        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = self.decrypt_data(encrypted_data)

        with open(file_path, 'wb') as f:
            if isinstance(decrypted_data, str):
                f.write(decrypted_data.encode())
            else:
                f.write(json.dumps(decrypted_data).encode())
