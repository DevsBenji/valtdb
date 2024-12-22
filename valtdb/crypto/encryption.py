"""
Encryption and decryption utilities for ValtDB.
"""
import json
import ast
from enum import Enum
from typing import Any, Dict, Union, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from ..keypair import KeyPair

class EncryptionAlgorithm(Enum):
    """Supported encryption algorithms"""
    RSA = "rsa"
    AES = "aes"

class HashAlgorithm(Enum):
    """Supported hash algorithms"""
    SHA256 = "sha256"

class KeyPair:
    """Container for asymmetric encryption keys"""
    def __init__(self, private_key: Any = None, public_key: Any = None):
        self.private_key = private_key
        self.public_key = public_key

    @property
    def has_private_key(self):
        return self.private_key is not None

def generate_keypair() -> KeyPair:
    """Generate a new key pair.
    
    Returns:
        KeyPair: A new key pair
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return KeyPair(private_key, public_key)

def encrypt_data(data: Union[str, Dict[str, Any]], key: Union[rsa.RSAPublicKey, bytes]) -> bytes:
    """Encrypt data using public key or symmetric key.
    
    Args:
        data: Data to encrypt
        key: Public key or symmetric key to use for encryption
    
    Returns:
        bytes: Encrypted data
    """
    if isinstance(data, dict):
        data = json.dumps(data)
    elif not isinstance(data, str):
        data = str(data)
    
    data_bytes = data.encode()
    
    if isinstance(key, rsa.RSAPublicKey):
        # For RSA, we need to use symmetric encryption for large data
        fernet_key = Fernet.generate_key()
        fernet = Fernet(fernet_key)
        
        # Encrypt data with Fernet
        encrypted_data = fernet.encrypt(data_bytes)
        
        # Encrypt Fernet key with RSA
        encrypted_key = key.encrypt(
            fernet_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Combine encrypted key and data
        return encrypted_key + b":" + encrypted_data
    else:
        # For symmetric encryption, just use Fernet directly
        fernet = Fernet(key)
        return fernet.encrypt(data_bytes)

def decrypt_data(encrypted_data: bytes, key: Union[rsa.RSAPrivateKey, bytes]) -> Union[str, Dict[str, Any]]:
    """Decrypt data using private key or symmetric key.
    
    Args:
        encrypted_data: Encrypted data
        key: Private key or symmetric key to use for decryption
    
    Returns:
        Union[str, Dict[str, Any]]: Decrypted data
    """
    if isinstance(key, rsa.RSAPrivateKey):
        # Split encrypted key and data
        encrypted_key, encrypted_content = encrypted_data.split(b":", 1)
        
        # Decrypt Fernet key
        fernet_key = key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt data with Fernet
        fernet = Fernet(fernet_key)
        decrypted = fernet.decrypt(encrypted_content)
    else:
        # For symmetric decryption, just use Fernet directly
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_data)
    
    decrypted_str = decrypted.decode()
    try:
        return json.loads(decrypted_str)
    except json.JSONDecodeError:
        return decrypted_str

def hash_data(data: Dict[str, Any]) -> str:
    """Generate hash for data.
    
    Args:
        data: Data to hash
    
    Returns:
        str: Hash of data
    """
    data_str = json.dumps(data, sort_keys=True)
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(data_str.encode())
    return hasher.finalize().hex()

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
        hash_algorithm: Optional[HashAlgorithm] = HashAlgorithm.SHA256
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
        return encrypt_data(data, self.keypair.public_key)

    def decrypt(self, encrypted_data: bytes) -> Union[str, Dict[str, Any]]:
        """Decrypt data using the private key"""
        if not self.keypair.has_private_key:
            raise ValueError("Cannot decrypt without private key")
        return decrypt_data(encrypted_data, self.keypair.private_key)
