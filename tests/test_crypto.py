import unittest
from valtdb.crypto import (
    generate_keypair,
    encrypt_data,
    decrypt_data,
    hash_data,
    verify_hash
)

class TestCrypto(unittest.TestCase):
    def setUp(self):
        """Set up test keys"""
        self.keypair = generate_keypair()

    def test_keypair_generation(self):
        """Test key pair generation"""
        self.assertIsNotNone(self.keypair.private_key)
        self.assertIsNotNone(self.keypair.public_key)

    def test_encryption_decryption(self):
        """Test data encryption and decryption"""
        test_data = {
            "string": "test string",
            "number": 12345,
            "list": [1, 2, 3],
            "dict": {"key": "value"}
        }
        
        # Encrypt data
        encrypted = encrypt_data(test_data, self.keypair.public_key)
        self.assertIsInstance(encrypted, bytes)
        
        # Decrypt data
        decrypted = decrypt_data(encrypted, self.keypair.private_key)
        self.assertEqual(decrypted, test_data)

    def test_hashing(self):
        """Test data hashing"""
        test_data = {"id": 1, "name": "test"}
        
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
        large_data = {
            "large_string": "x" * 1000000,  # 1MB string
            "large_list": list(range(10000))
        }
        
        # Encrypt and decrypt
        encrypted = encrypt_data(large_data, self.keypair.public_key)
        decrypted = decrypt_data(encrypted, self.keypair.private_key)
        self.assertEqual(decrypted, large_data)

    def test_invalid_decryption(self):
        """Test decryption with wrong key"""
        test_data = "test string"
        wrong_keypair = generate_keypair()
        
        # Encrypt with one key
        encrypted = encrypt_data(test_data, self.keypair.public_key)
        
        # Try to decrypt with wrong key
        with self.assertRaises(Exception):
            decrypt_data(encrypted, wrong_keypair.private_key)

    def test_encryption_decryption_with_all_algorithms(self):
        """Test encryption and decryption with all algorithms"""
        test_data = "Hello, World!"
        encryption_algorithms = ["AES", "RSA", "ChaCha20", "TripleDES"]
        
        for algorithm in encryption_algorithms:
            # Encrypt data
            encrypted = encrypt_data(test_data, self.keypair.public_key, algorithm)
            self.assertIsInstance(encrypted, bytes)
            
            # Decrypt data
            decrypted = decrypt_data(encrypted, self.keypair.private_key, algorithm)
            self.assertEqual(decrypted, test_data)

    def test_password_hashing_with_all_algorithms(self):
        """Test password hashing with all algorithms"""
        test_password = "SecurePassword123"
        hash_algorithms = ["SHA256", "BCRYPT", "ARGON2", "BLAKE2b"]
        
        for algorithm in hash_algorithms:
            # Hash password
            hashed = hash_data(test_password, algorithm)
            self.assertIsInstance(hashed, str)
            
            # Verify correct password
            self.assertTrue(verify_hash(test_password, hashed, algorithm))
            
            # Verify incorrect password
            self.assertFalse(verify_hash("WrongPassword", hashed, algorithm))

if __name__ == '__main__':
    unittest.main()
