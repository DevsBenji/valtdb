"""
Performance tests for ValtDB
"""

import os
import shutil
import tempfile
import time
from typing import Any, Dict, List
import random

import pytest

from valtdb.api import ValtDB
from valtdb.crypto.encryption import EncryptionManager
from valtdb.schema import DataType
from valtdb.query import Query, Operator
from valtdb.database import Database

class TestPerformance:
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db = Database(self.test_dir)
        self.test_schema = {
            "fields": {
                "id": {"type": "INTEGER"},
                "name": {"type": "STRING"},
                "age": {"type": "INTEGER"},
                "active": {"type": "BOOLEAN"},
                "created_at": {"type": "DATETIME"}
            }
        }
        self.table = self.db.create_table("test", self.test_schema)
        self.sample_size = 1000

    def tearDown(self):
        self.db.close()
        for file in os.listdir(self.test_dir):
            os.remove(os.path.join(self.test_dir, file))
        os.rmdir(self.test_dir)

    def generate_random_string(self, length: int = 10) -> str:
        import string
        return ''.join(random.choices(string.ascii_letters, k=length))

    def generate_sample_data(self) -> Dict[str, Any]:
        from datetime import datetime
        return {
            "id": random.randint(1, 1000000),
            "name": self.generate_random_string(),
            "age": random.randint(18, 80),
            "active": random.choice([True, False]),
            "created_at": datetime.now().isoformat()
        }

    def test_bulk_insert_performance(self):
        start_time = time.time()
        for _ in range(self.sample_size):
            self.table.insert(self.generate_sample_data())
        end_time = time.time()
        
        print(f"\nBulk insert of {self.sample_size} records took {end_time - start_time:.2f} seconds")
        assert end_time - start_time < 5.0  # Should complete within 5 seconds

    def test_query_performance(self):
        # Insert test data
        for _ in range(self.sample_size):
            self.table.insert(self.generate_sample_data())

        # Test different query operations
        start_time = time.time()
        
        # Simple equality query
        query = Query().filter("active", Operator.EQUALS, True)
        results = self.table.select(query)
        
        # Range query
        query = Query().filter("age", Operator.GREATER_THAN, 30).filter("age", Operator.LESS_THAN, 50)
        results = self.table.select(query)
        
        # Multiple conditions
        query = (Query()
                .filter("active", Operator.EQUALS, True)
                .filter("age", Operator.GREATER_THAN, 25))
        results = self.table.select(query)
        
        end_time = time.time()
        
        print(f"\nThree complex queries on {self.sample_size} records took {end_time - start_time:.2f} seconds")
        assert end_time - start_time < 1.0  # Should complete within 1 second

    def test_update_performance(self):
        # Insert test data
        for _ in range(self.sample_size):
            self.table.insert(self.generate_sample_data())

        start_time = time.time()
        
        # Update half of the records
        query = Query().filter("age", Operator.LESS_THAN, 50)
        self.table.update(query, {"active": False})
        
        end_time = time.time()
        
        print(f"\nUpdating ~50% of {self.sample_size} records took {end_time - start_time:.2f} seconds")
        assert end_time - start_time < 1.0  # Should complete within 1 second

    def test_delete_performance(self):
        # Insert test data
        for _ in range(self.sample_size):
            self.table.insert(self.generate_sample_data())

        start_time = time.time()
        
        # Delete half of the records
        query = Query().filter("age", Operator.GREATER_THAN, 50)
        self.table.delete(query)
        
        end_time = time.time()
        
        print(f"\nDeleting ~50% of {self.sample_size} records took {end_time - start_time:.2f} seconds")
        assert end_time - start_time < 1.0  # Should complete within 1 second

    def test_encrypted_performance(self):
        # Create encrypted database
        from valtdb.crypto import generate_keypair
        keypair = generate_keypair()
        encrypted_db = Database(os.path.join(self.test_dir, "encrypted"), str(keypair.private_key))
        
        encrypted_schema = {
            "fields": {
                "id": {"type": "INTEGER"},
                "secret": {"type": "STRING", "encrypted": True},
                "value": {"type": "FLOAT", "encrypted": True}
            }
        }
        
        encrypted_table = encrypted_db.create_table("encrypted_test", encrypted_schema)
        
        # Test encrypted operations
        start_time = time.time()
        
        # Insert encrypted data
        for _ in range(100):  # Smaller sample size for encrypted operations
            encrypted_table.insert({
                "id": random.randint(1, 1000),
                "secret": self.generate_random_string(20),
                "value": random.uniform(0, 1000)
            })
        
        # Query encrypted data
        query = Query().filter("id", Operator.LESS_THAN, 500)
        results = encrypted_table.select(query)
        
        end_time = time.time()
        
        print(f"\nEncrypted operations took {end_time - start_time:.2f} seconds")
        assert end_time - start_time < 2.0  # Should complete within 2 seconds
        
        encrypted_db.close()

if __name__ == '__main__':
    pytest.main()
