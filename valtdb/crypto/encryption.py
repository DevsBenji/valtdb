"""
Encryption and hashing utilities for ValtDB
"""
from typing import Optional, Union, Dict, Any
from enum import Enum
import os
import base64
import hashlib
import ast
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

def generate_keypair() -> KeyPair:
    """Generate a new RSA key pair.
    
    Returns:
        KeyPair: A new RSA key pair
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return KeyPair(private_key, public_key)

def encrypt_data(data: Union[str, bytes, Dict], key: Any) -> bytes:
    """Encrypt data using the specified key.
    
    Args:
        data: Data to encrypt
        key: Encryption key
    
    Returns:
        bytes: Encrypted data
    """
    if isinstance(data, dict):
        data = str(data).encode()
    elif isinstance(data, str):
        data = data.encode()
    
    if isinstance(key, rsa.RSAPublicKey):
        return key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    else:
        fernet = Fernet(key)
        return fernet.encrypt(data)

def decrypt_data(encrypted_data: bytes, key: Any) -> Union[str, Dict]:
    """Decrypt data using the specified key.
    
    Args:
        encrypted_data: Data to decrypt
        key: Decryption key
    
    Returns:
        Union[str, Dict]: Decrypted data
    """
    if isinstance(key, rsa.RSAPrivateKey):
        decrypted = key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    else:
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_data)
    
    try:
        return ast.literal_eval(decrypted.decode())
    except (ValueError, SyntaxError):
        return decrypted.decode()

def hash_data(data: Union[str, bytes], salt: Optional[bytes] = None) -> bytes:
    """Hash data using SHA-256.
    
    Args:
        data: Data to hash
        salt: Optional salt for the hash
    
    Returns:
        bytes: Hashed data
    """
    if isinstance(data, str):
        data = data.encode()
    
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    return salt + kdf.derive(data)

def verify_hash(data: Union[str, bytes], hash_value: bytes) -> bool:
    """Verify that data matches a hash.
    
    Args:
        data: Data to verify
        hash_value: Hash to verify against
    
    Returns:
        bool: True if data matches hash
    """
    if isinstance(data, str):
        data = data.encode()
    
    salt = hash_value[:16]
    stored_key = hash_value[16:]
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    try:
        kdf.verify(data, stored_key)
        return True
    except InvalidKey:
        return False
