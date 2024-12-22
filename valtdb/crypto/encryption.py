"""
Encryption and decryption utilities for ValtDB.
"""

import ast
import json
from enum import Enum
from typing import Any, Dict, Optional, Union

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ..keypair import KeyPair


class EncryptionAlgorithm(Enum):
    """Supported encryption algorithms"""

    RSA = "rsa"
    AES = "aes"


class HashAlgorithm(Enum):
    """Supported hash algorithms"""

    SHA256 = "sha256"


def generate_keypair() -> KeyPair:
    """Generate a new key pair.

    Returns:
        KeyPair: A new key pair
    """
    private_key: rsa.RSAPrivateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key: rsa.RSAPublicKey = private_key.public_key()
    return KeyPair(private_key, public_key)


def encrypt_data(data: Union[str, Dict[str, Any]], key: Union[rsa.RSAPublicKey, bytes]) -> bytes:
    """Encrypt data using public key or symmetric key.

    Args:
        data: Data to encrypt
        key: Public key or symmetric key to use for encryption

    Returns:
        bytes: Encrypted data
    """
    # If data is a dictionary, convert to JSON
    if isinstance(data, dict):
        data_bytes = json.dumps(data, sort_keys=True).encode('utf-8')
    # If data is a string, convert to bytes
    elif isinstance(data, str):
        data_bytes = data.encode('utf-8')
    else:
        raise TypeError(f"Unsupported data type for encryption: {type(data)}")

    # If key is a public key (RSA), use asymmetric encryption
    if isinstance(key, rsa.RSAPublicKey):
        return key.encrypt(
            data_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    # If key is symmetric (bytes), use Fernet symmetric encryption
    elif isinstance(key, bytes):
        f = Fernet(key)
        return f.encrypt(data_bytes)
    
    else:
        raise TypeError(f"Unsupported key type for encryption: {type(key)}")


def decrypt_data(
    encrypted_data: bytes, 
    key: Union[rsa.RSAPrivateKey, bytes]
) -> Union[str, Dict[str, Any]]:
    """Decrypt data using private key or symmetric key.

    Args:
        encrypted_data: Encrypted data
        key: Private key or symmetric key to use for decryption

    Returns:
        Union[str, Dict[str, Any]]: Decrypted data
    """
    # If key is an RSA private key, use RSA decryption
    if isinstance(key, rsa.RSAPrivateKey):
        decrypted_bytes = key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    # If key is symmetric (bytes), use Fernet symmetric decryption
    elif isinstance(key, bytes):
        f = Fernet(key)
        decrypted_bytes = f.decrypt(encrypted_data)
    
    else:
        raise TypeError(f"Unsupported key type for decryption: {type(key)}")

    # Try to parse as JSON, otherwise return as string
    try:
        # Explicitly type the return value as Dict[str, Any]
        decoded_data: Dict[str, Any] = json.loads(decrypted_bytes.decode('utf-8'))
        return decoded_data
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Explicitly type the return value as str
        decoded_str: str = decrypted_bytes.decode('utf-8')
        return decoded_str


def hash_data(data: Dict[str, Any]) -> str:
    """Generate hash for data.

    Args:
        data: Data to hash

    Returns:
        str: Hash of data
    """
    # Convert dictionary to a sorted, consistent string representation
    data_str = json.dumps(data, sort_keys=True)
    
    # Create a hash object
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data_str.encode('utf-8'))
    
    # Return hexadecimal representation of hash
    return digest.finalize().hex()


def verify_hash(data: Dict[str, Any], hash_value: str) -> bool:
    """Verify hash for data.

    Args:
        data: Data to verify
        hash_value: Hash to verify against

    Returns:
        bool: True if hash matches, False otherwise
    """
    return hash_data(data) == hash_value


class EncryptionManager:
    """Manage encryption and decryption operations"""

    def __init__(
        self,
        keypair: Optional[KeyPair] = None,
        encryption_algorithm: Optional[EncryptionAlgorithm] = EncryptionAlgorithm.RSA,
        hash_algorithm: Optional[HashAlgorithm] = HashAlgorithm.SHA256,
    ):
        """
        Initialize encryption manager.

        Args:
            keypair: Optional KeyPair for encryption and decryption
            encryption_algorithm: Encryption algorithm to use
            hash_algorithm: Hash algorithm to use
        """
        self.keypair = keypair or generate_keypair()
        self.encryption_algorithm = encryption_algorithm
        self.hash_algorithm = hash_algorithm

    def encrypt(self, data: Union[str, Dict[str, Any]]) -> bytes:
        """Encrypt data using the public key"""
        if not self.keypair.public_key:
            raise ValueError("No public key available for encryption")
        
        return encrypt_data(data, self.keypair.public_key)

    def decrypt(self, encrypted_data: bytes) -> Union[str, Dict[str, Any]]:
        """Decrypt data using the private key"""
        if not self.keypair.private_key:
            raise ValueError("No private key available for decryption")
        
        return decrypt_data(encrypted_data, self.keypair.private_key)

    def hash(self, data: Dict[str, Any]) -> str:
        """Generate hash for data"""
        return hash_data(data)

    def verify_hash(self, data: Dict[str, Any], hash_value: str) -> bool:
        """Verify hash for data"""
        return verify_hash(data, hash_value)
