import os
import tempfile
import unittest

from valtdb import Database
from valtdb.crypto import generate_keypair
from valtdb.exceptions import ValtDBError


class TestDatabase(unittest.TestCase):
    def setUp(self):
        """Set up test database"""
        self.test_dir = tempfile.mkdtemp()
        self.db_name = "test_db"
        self.keypair = generate_keypair()
        self.db = Database(self.db_name, path=self.test_dir, keypair=self.keypair)

    def tearDown(self):
        """Clean up test files"""
        for file in os.listdir(self.test_dir):
            os.remove(os.path.join(self.test_dir, file))
        os.rmdir(self.test_dir)

    def test_create_database(self):
        """Test database creation"""
        self.assertTrue(os.path.exists(os.path.join(self.test_dir, f"{self.db_name}.valt")))

    def test_create_table(self):
        """Test table creation"""
        schema = {"id": "int", "name": "str"}
        table = self.db.create_table("test_table", schema)
        self.assertIn("test_table", self.db.list_tables())
        self.assertEqual(table.schema, schema)

    def test_encrypted_table(self):
        """Test encrypted table operations"""
        schema = {"id": "int", "name": "encrypted_str", "salary": "encrypted_int"}
        table = self.db.create_table("employees", schema)

        # Test data
        test_data = {"id": 1, "name": "John Doe", "salary": 50000}

        # Insert
        table.insert(test_data)

        # Select
        result = table.select({"id": 1})[0]
        self.assertEqual(result["name"], test_data["name"])
        self.assertEqual(result["salary"], test_data["salary"])

    def test_data_integrity(self):
        """Test data integrity checking"""
        schema = {"id": "int", "name": "str"}
        table = self.db.create_table("integrity_test", schema)

        # Insert test data
        table.insert({"id": 1, "name": "Test"})

        # Verify data can be retrieved
        result = table.select({"id": 1})[0]
        self.assertEqual(result["name"], "Test")

    def test_invalid_schema(self):
        """Test schema validation"""
        schema = {"id": "invalid_type"}
        with self.assertRaises(ValtDBError):
            self.db.create_table("invalid_table", schema)

    def test_table_operations(self):
        """Test basic table operations"""
        schema = {"id": "int", "name": "str"}
        table = self.db.create_table("ops_test", schema)

        # Insert
        table.insert({"id": 1, "name": "Test1"})
        table.insert({"id": 2, "name": "Test2"})

        # Select
        results = table.select({"name": "Test1"})
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], 1)

        # Update
        table.update({"id": 1}, {"name": "Updated"})
        result = table.select({"id": 1})[0]
        self.assertEqual(result["name"], "Updated")

        # Delete
        table.delete({"id": 1})
        results = table.select({"id": 1})
        self.assertEqual(len(results), 0)


if __name__ == "__main__":
    unittest.main()
