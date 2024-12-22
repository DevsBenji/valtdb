import unittest
from typing import Dict, Any, Union

from cryptography.hazmat.primitives.asymmetric import rsa

from valtdb.crypto.encryption import decrypt_data, encrypt_data, generate_keypair, hash_data, verify_hash
from valtdb.keypair import KeyPair


class TestCrypto(unittest.TestCase):
    def setUp(self):
        """Set up test keys"""
        self.keypair: KeyPair = generate_keypair()
        self.public_key: rsa.RSAPublicKey = self.keypair.public_key
        self.private_key: rsa.RSAPrivateKey = self.keypair.private_key

    def test_keypair_generation(self):
        """Test key pair generation"""
        self.assertIsNotNone(self.private_key)
        self.assertIsNotNone(self.public_key)

    def test_encryption_decryption(self):
        """Test data encryption and decryption"""
        test_data: Dict[str, Any] = {
            "string": "test string",
            "number": 12345,
            "list": [1, 2, 3],
            "dict": {"key": "value"},
        }

        # Ensure public and private keys are of the correct type
        self.assertIsInstance(self.public_key, rsa.RSAPublicKey)
        self.assertIsInstance(self.private_key, rsa.RSAPrivateKey)

        # Encrypt data
        encrypted = encrypt_data(test_data, self.public_key)
        self.assertIsInstance(encrypted, bytes)

        # Decrypt data
        decrypted = decrypt_data(encrypted, self.private_key)
        self.assertEqual(decrypted, test_data)

    def test_hashing(self):
        """Test data hashing"""
        test_data: Dict[str, Any] = {"id": 1, "name": "test"}

        # Create hash
        hash_value = hash_data(test_data)
        self.assertIsInstance(hash_value, str)
        self.assertEqual(len(hash_value), 64)  # SHA256 produces 64 character hex string

        # Verify hash
        self.assertTrue(verify_hash(test_data, hash_value))

        # Verify hash with modified data
        modified_data = test_data.copy()
        modified_data["name"] = "modified"
        self.assertFalse(verify_hash(modified_data, hash_value))

    def test_large_data_encryption(self):
        """Test encryption of large data"""
        # Large dictionary to test encryption
        large_test_data: Dict[str, Any] = {
            "large_string": "x" * 10000,
            "large_list": list(range(10000)),
            "nested_dict": {"a": list(range(1000)), "b": {"c": "x" * 1000}}
        }

        # Encrypt data
        encrypted = encrypt_data(large_test_data, self.public_key)
        self.assertIsInstance(encrypted, bytes)

        # Decrypt data
        decrypted = decrypt_data(encrypted, self.private_key)
        self.assertEqual(decrypted, large_test_data)

    def test_invalid_decryption(self):
        """Test decryption with wrong key"""
        # Generate another keypair
        other_keypair: KeyPair = generate_keypair()

        # Ensure keypairs are different
        self.assertNotEqual(self.private_key, other_keypair.private_key)
        self.assertNotEqual(self.public_key, other_keypair.public_key)

        # Test data
        test_data: Dict[str, Any] = {"message": "secret data"}

        # Encrypt with one key
        encrypted = encrypt_data(test_data, self.public_key)

        # Try to decrypt with another key (should fail)
        with self.assertRaises(Exception):
            decrypt_data(encrypted, other_keypair.private_key)

    def test_symmetric_encryption(self):
        """Test symmetric encryption with Fernet key"""
        # Symmetric key
        symmetric_key = b'mysecretkey1234567890123456789012'

        # Test data
        test_data: Dict[str, Any] = {"sensitive": "information"}

        # Encrypt with symmetric key
        encrypted = encrypt_data(test_data, symmetric_key)
        self.assertIsInstance(encrypted, bytes)

        # Decrypt with same symmetric key
        decrypted = decrypt_data(encrypted, symmetric_key)
        self.assertEqual(decrypted, test_data)

    def test_different_data_types(self):
        """Test encryption with various data types"""
        test_cases: Dict[str, Union[str, int, float, list, dict]] = {
            "simple_string": "hello world",
            "integer": 42,
            "float": 3.14,
            "list": [1, 2, 3],
            "nested_dict": {"a": {"b": {"c": "deep"}}}
        }

        for name, data in test_cases.items():
            with self.subTest(name=name):
                # Convert to dict if not already a dict
                data_dict: Dict[str, Any] = data if isinstance(data, dict) else {"value": data}
                
                # Encrypt data
                encrypted = encrypt_data(data_dict, self.public_key)
                self.assertIsInstance(encrypted, bytes)

                # Decrypt data
                decrypted = decrypt_data(encrypted, self.private_key)
                self.assertEqual(decrypted, data_dict)


if __name__ == "__main__":
    unittest.main()
