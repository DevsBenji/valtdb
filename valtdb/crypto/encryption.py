"""
Encryption and hashing utilities for ValtDB
"""
from typing import Optional, Union, Dict, Any
from enum import Enum
import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidKey

class EncryptionAlgorithm(Enum):
    """Supported encryption algorithms"""
    AES = "aes"
    FERNET = "fernet"
    RSA = "rsa"
    CHACHA20 = "chacha20"
    TRIPLE_DES = "3des"

class HashAlgorithm(Enum):
    """Supported hash algorithms"""
    SHA256 = "sha256"
    SHA512 = "sha512"
    BLAKE2B = "blake2b"
    ARGON2 = "argon2"
    BCRYPT = "bcrypt"

class KeyPair:
    """Container for asymmetric encryption keys"""
    def __init__(self, private_key: Any, public_key: Any):
        self.private_key = private_key
        self.public_key = public_key

class EncryptionManager:
    """Manages encryption and hashing operations"""
    
    def __init__(self, 
                 encryption_algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES,
                 hash_algorithm: HashAlgorithm = HashAlgorithm.SHA256):
        self.encryption_algorithm = encryption_algorithm
        self.hash_algorithm = hash_algorithm
        self._setup_encryption()
        self._setup_hashing()

    def _setup_encryption(self):
        """Initialize encryption components"""
        if self.encryption_algorithm == EncryptionAlgorithm.AES:
            self.key = os.urandom(32)
            self.iv = os.urandom(16)
        elif self.encryption_algorithm == EncryptionAlgorithm.FERNET:
            self.key = Fernet.generate_key()
            self.fernet = Fernet(self.key)
        elif self.encryption_algorithm == EncryptionAlgorithm.RSA:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            self.public_key = self.private_key.public_key()
        elif self.encryption_algorithm == EncryptionAlgorithm.CHACHA20:
            self.key = os.urandom(32)
            self.nonce = os.urandom(16)
        elif self.encryption_algorithm == EncryptionAlgorithm.TRIPLE_DES:
            self.key = os.urandom(24)
            self.iv = os.urandom(8)

    def _setup_hashing(self):
        """Initialize hashing components"""
        self.salt = os.urandom(16)
        if self.hash_algorithm == HashAlgorithm.ARGON2:
            try:
                import argon2
                self.argon2_hasher = argon2.PasswordHasher()
            except ImportError:
                raise ImportError("argon2-cffi package is required for Argon2 hashing")
        elif self.hash_algorithm == HashAlgorithm.BCRYPT:
            try:
                import bcrypt
                self.bcrypt = bcrypt
            except ImportError:
                raise ImportError("bcrypt package is required for bcrypt hashing")

    def encrypt(self, data: Union[str, bytes]) -> bytes:
        """Encrypt data using the selected algorithm"""
        if isinstance(data, str):
            data = data.encode()

        if self.encryption_algorithm == EncryptionAlgorithm.AES:
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))
            encryptor = cipher.encryptor()
            padded_data = self._pad_data(data)
            return encryptor.update(padded_data) + encryptor.finalize()

        elif self.encryption_algorithm == EncryptionAlgorithm.FERNET:
            return self.fernet.encrypt(data)

        elif self.encryption_algorithm == EncryptionAlgorithm.RSA:
            return self.public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

        elif self.encryption_algorithm == EncryptionAlgorithm.CHACHA20:
            cipher = Cipher(algorithms.ChaCha20(self.key, self.nonce), mode=None)
            encryptor = cipher.encryptor()
            return encryptor.update(data)

        elif self.encryption_algorithm == EncryptionAlgorithm.TRIPLE_DES:
            cipher = Cipher(algorithms.TripleDES(self.key), modes.CBC(self.iv))
            encryptor = cipher.encryptor()
            padded_data = self._pad_data(data)
            return encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using the selected algorithm"""
        if self.encryption_algorithm == EncryptionAlgorithm.AES:
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            return self._unpad_data(padded_data)

        elif self.encryption_algorithm == EncryptionAlgorithm.FERNET:
            return self.fernet.decrypt(encrypted_data)

        elif self.encryption_algorithm == EncryptionAlgorithm.RSA:
            return self.private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

        elif self.encryption_algorithm == EncryptionAlgorithm.CHACHA20:
            cipher = Cipher(algorithms.ChaCha20(self.key, self.nonce), mode=None)
            decryptor = cipher.decryptor()
            return decryptor.update(encrypted_data)

        elif self.encryption_algorithm == EncryptionAlgorithm.TRIPLE_DES:
            cipher = Cipher(algorithms.TripleDES(self.key), modes.CBC(self.iv))
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            return self._unpad_data(padded_data)

    def hash_password(self, password: str) -> str:
        """Hash password using the selected algorithm"""
        if isinstance(password, str):
            password = password.encode()

        if self.hash_algorithm == HashAlgorithm.SHA256:
            return hashlib.sha256(password + self.salt).hexdigest()

        elif self.hash_algorithm == HashAlgorithm.SHA512:
            return hashlib.sha512(password + self.salt).hexdigest()

        elif self.hash_algorithm == HashAlgorithm.BLAKE2B:
            return hashlib.blake2b(password + self.salt).hexdigest()

        elif self.hash_algorithm == HashAlgorithm.ARGON2:
            return self.argon2_hasher.hash(password)

        elif self.hash_algorithm == HashAlgorithm.BCRYPT:
            return self.bcrypt.hashpw(password, self.bcrypt.gensalt()).decode()

    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against its hash"""
        if isinstance(password, str):
            password = password.encode()

        if self.hash_algorithm in [HashAlgorithm.SHA256, HashAlgorithm.SHA512, HashAlgorithm.BLAKE2B]:
            return self.hash_password(password) == hashed

        elif self.hash_algorithm == HashAlgorithm.ARGON2:
            try:
                self.argon2_hasher.verify(hashed, password)
                return True
            except Exception:
                return False

        elif self.hash_algorithm == HashAlgorithm.BCRYPT:
            try:
                return self.bcrypt.checkpw(password, hashed.encode())
            except Exception:
                return False

    def _pad_data(self, data: bytes) -> bytes:
        """PKCS7 padding"""
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def _unpad_data(self, padded_data: bytes) -> bytes:
        """Remove PKCS7 padding"""
        padding_length = padded_data[-1]
        return padded_data[:-padding_length]

    def export_key(self) -> Dict[str, Any]:
        """Export encryption keys"""
        if self.encryption_algorithm == EncryptionAlgorithm.RSA:
            private_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return {
                "algorithm": self.encryption_algorithm.value,
                "private_key": base64.b64encode(private_pem).decode(),
                "public_key": base64.b64encode(public_pem).decode()
            }
        else:
            key_data = {
                "algorithm": self.encryption_algorithm.value,
                "key": base64.b64encode(self.key).decode()
            }
            if hasattr(self, 'iv'):
                key_data["iv"] = base64.b64encode(self.iv).decode()
            if hasattr(self, 'nonce'):
                key_data["nonce"] = base64.b64encode(self.nonce).decode()
            return key_data

    def import_key(self, key_data: Dict[str, Any]):
        """Import encryption keys"""
        if key_data["algorithm"] == EncryptionAlgorithm.RSA.value:
            private_pem = base64.b64decode(key_data["private_key"])
            self.private_key = serialization.load_pem_private_key(
                private_pem,
                password=None
            )
            self.public_key = self.private_key.public_key()
        else:
            self.key = base64.b64decode(key_data["key"])
            if "iv" in key_data:
                self.iv = base64.b64decode(key_data["iv"])
            if "nonce" in key_data:
                self.nonce = base64.b64decode(key_data["nonce"])
            if self.encryption_algorithm == EncryptionAlgorithm.FERNET:
                self.fernet = Fernet(self.key)
