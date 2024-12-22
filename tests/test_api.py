"""
Tests for ValtDB API
"""
import pytest
import tempfile
import os
from pathlib import Path
from valtdb.api import ValtDB
from valtdb.exceptions import ValtDBError

@pytest.fixture
def temp_dir():
    """Create temporary directory for tests"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir

@pytest.fixture
def db(temp_dir):
    """Create ValtDB instance"""
    return ValtDB(temp_dir)

def test_database_operations(db):
    """Test database operations"""
    # Create simple database
    db.db("testdb")
    assert os.path.exists(os.path.join(db.base_path, "testdb"))
    
    # Create encrypted database
    db.db("encrypted_db", {
        "algorithm": "AES",
        "hash_algorithm": "SHA256"
    })
    assert os.path.exists(os.path.join(db.base_path, "encrypted_db"))

def test_table_operations(db):
    """Test table operations"""
    # Simple schema
    users = db.db("testdb").table("users", {
        "id": "int",
        "name": "str",
        "email": {"type": "str", "unique": True},
        "password": {"type": "str", "encrypted": True}
    })
    
    assert "users" in db.tables()
    
    # Drop table
    db.drop_table("users")
    assert "users" not in db.tables()

def test_data_operations(db):
    """Test data operations"""
    # Setup
    users = db.db("testdb").table("users", {
        "id": "int",
        "name": "str",
        "age": "int",
        "status": "str"
    })
    
    # Insert single record
    users.insert({
        "id": 1,
        "name": "John Doe",
        "age": 30,
        "status": "active"
    })
    
    # Insert multiple records
    users.insert([
        {"id": 2, "name": "Jane Doe", "age": 25, "status": "active"},
        {"id": 3, "name": "Bob Smith", "age": 45, "status": "inactive"}
    ])
    
    # Simple select
    results = users.select()
    assert len(results) == 3
    
    # Select with where clause
    active_users = users.where(status="active").select()
    assert len(active_users) == 2
    
    # Select with complex conditions
    adult_users = users.where(
        age=("GT", 20),
        status="active"
    ).select()
    assert len(adult_users) == 2
    
    # Select specific fields
    names = users.select("name")
    assert all("name" in user and len(user) == 1 for user in names)
    
    # Update data
    updated = users.where(id=1).update({"status": "inactive"})
    assert updated == 1
    
    # Verify update
    inactive_users = users.where(status="inactive").select()
    assert len(inactive_users) == 2
    
    # Delete data
    deleted = users.where(status="inactive").delete()
    assert deleted == 2
    
    # Verify delete
    remaining = users.select()
    assert len(remaining) == 1

def test_query_builder(db):
    """Test query builder features"""
    users = db.db("testdb").table("users", {
        "id": "int",
        "name": "str",
        "age": "int",
        "role": "str"
    })
    
    # Insert test data
    users.insert([
        {"id": 1, "name": "Admin", "age": 30, "role": "admin"},
        {"id": 2, "name": "User1", "age": 25, "role": "user"},
        {"id": 3, "name": "User2", "age": 35, "role": "user"}
    ])
    
    # Test OR conditions
    results = users.where(
        age=("GT", 30)
    ).or_where(
        role="admin"
    ).select()
    assert len(results) == 2
    
    # Test first() method
    admin = users.where(role="admin").first()
    assert admin["name"] == "Admin"
    
    # Test exists() method
    assert users.where(role="admin").exists()
    assert not users.where(role="guest").exists()
    
    # Test count() method
    assert users.where(role="user").count() == 2

def test_pagination(db):
    """Test pagination features"""
    posts = db.db("testdb").table("posts", {
        "id": "int",
        "title": "str"
    })
    
    # Insert test data
    posts.insert([
        {"id": i, "title": f"Post {i}"} for i in range(1, 16)
    ])
    
    # Test pagination
    page1, meta1 = posts.paginate(page=1, per_page=5)
    assert len(page1) == 5
    assert meta1["total"] == 15
    assert meta1["current_page"] == 1
    assert meta1["last_page"] == 3
    
    # Test last page
    page3, meta3 = posts.paginate(page=3, per_page=5)
    assert len(page3) == 5
    assert meta3["from"] == 11
    assert meta3["to"] == 15

def test_error_handling(db):
    """Test error handling"""
    with pytest.raises(ValtDBError, match="No database selected"):
        db.table("users")
    
    users = db.db("testdb").table("users", {
        "id": {"type": "int", "unique": True},
        "name": "str"
    })
    
    # Test unique constraint
    users.insert({"id": 1, "name": "Test"})
    with pytest.raises(ValtDBError):
        users.insert({"id": 1, "name": "Test2"})

def test_backup_restore(db):
    """Test backup and restore functionality"""
    users = db.db("testdb").table("users", {
        "id": "int",
        "name": "str"
    })
    
    # Insert test data
    users.insert({"id": 1, "name": "Test"})
    
    # Backup
    with tempfile.TemporaryDirectory() as backup_dir:
        backup_file = db.backup(backup_dir)
        
        # Delete all data
        users.where().delete()
        assert users.count() == 0
        
        # Restore
        db.restore(backup_file)
        assert users.count() == 1
        assert users.first()["name"] == "Test"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
