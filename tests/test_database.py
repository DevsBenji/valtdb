import os
import tempfile
import unittest
from datetime import datetime

from valtdb.database import Database
from valtdb.exceptions import ValtDBError
from valtdb.table import Schema, SchemaField, DataType
from valtdb.query import Query, Operator

class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db = Database(self.test_dir)
        self.test_schema = {
            "fields": {
                "id": {"type": "integer"},
                "name": {"type": "string"},
                "active": {"type": "boolean"}
            }
        }
        self.table = self.db.create_table("test", self.test_schema)

    def tearDown(self):
        self.db.close()
        for file in os.listdir(self.test_dir):
            os.remove(os.path.join(self.test_dir, file))
        os.rmdir(self.test_dir)

    def test_create_table(self):
        table = self.db.create_table("test", self.test_schema)
        self.assertIsNotNone(table)
        self.assertEqual(table.name, "test")
        self.assertTrue(os.path.exists(os.path.join(self.test_dir, "test.table")))

    def test_get_table(self):
        self.db.create_table("test", self.test_schema)
        table = self.db.get_table("test")
        self.assertIsNotNone(table)
        self.assertEqual(table.name, "test")

    def test_table_removal(self):
        """Test table removal."""
        self.db.create_table("test", self.test_schema)
        table_path = os.path.join(self.test_dir, "test.table")
        self.assertTrue(os.path.exists(table_path))
        
        # Remove table from database
        del self.db._tables["test"]
        # Remove table file
        os.remove(table_path)
        
        self.assertFalse(os.path.exists(table_path))
        with self.assertRaises(ValtDBError):
            self.db.get_table("test")

    def test_list_tables(self):
        self.db.create_table("test1", self.test_schema)
        self.db.create_table("test2", self.test_schema)
        tables = self.db.list_tables()
        self.assertEqual(len(tables), 2)
        self.assertIn("test1", tables)
        self.assertIn("test2", tables)

    def test_table_operations(self):
        table = self.db.create_table("test", self.test_schema)
        
        # Test insert
        table.insert({"id": 1, "name": "Test1", "active": True})
        table.insert({"id": 2, "name": "Test2", "active": False})
        
        # Test select with query
        query = Query().filter("id", Operator.EQUALS, 1)
        results = table.select(query)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "Test1")
        
        # Test update with query
        update_query = Query().filter("id", Operator.EQUALS, 2)
        table.update(update_query, {"active": True})
        results = table.select(update_query)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["active"])
        
        # Test delete with query
        delete_query = Query().filter("id", Operator.EQUALS, 1)
        table.delete(delete_query)
        results = table.select()
        self.assertEqual(len(results), 1)

    def test_delete(self):
        """Test deleting records."""
        # Insert test data
        self.table.insert({"id": 1, "name": "Alice"})
        self.table.insert({"id": 2, "name": "Bob"})
        
        # Create a query to delete
        delete_query = Query().filter("id", Operator.EQUALS, 1)
        
        # Delete record
        self.table.delete(delete_query)
        
        # Verify deletion
        results = self.table.select()
        assert len(results) == 1
        assert results[0]["id"] == 2

    def test_data_validation(self):
        table = self.db.create_table("test", self.test_schema)
        
        # Test valid data
        valid_data = {"id": 1, "name": "Test", "active": True}
        validated = self.db.validate_data("test", valid_data)
        self.assertEqual(validated["id"], 1)
        self.assertEqual(validated["name"], "Test")
        self.assertTrue(validated["active"])
        
        # Test invalid data
        invalid_data = {"id": "not_an_int", "name": "Test", "active": True}
        with self.assertRaises(ValtDBError):
            self.db.validate_data("test", invalid_data)

    def test_data_persistence(self):
        # Create table and insert data
        table = self.db.create_table("test", self.test_schema)
        table.insert({"id": 1, "name": "Test", "active": True})
        
        # Close and reopen database
        self.db.close()
        new_db = Database(self.test_dir)
        
        # Check if data persists
        table = new_db.get_table("test")
        results = table.select()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], 1)
        self.assertEqual(results[0]["name"], "Test")
        self.assertTrue(results[0]["active"])

if __name__ == '__main__':
    unittest.main()
