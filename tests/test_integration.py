"""
Integration tests for ValtDB
"""
import pytest
import tempfile
import os
from valtdb import Database
from valtdb.schema import Schema, SchemaField, DataType
from valtdb.query import Query, Operator
from valtdb.ssh import SSHConfig, RemoteDatabase
from valtdb.auth import AuthManager, RBAC
from valtdb.exceptions import ValtDBError

@pytest.fixture
def test_schema():
    return Schema([
        SchemaField("id", DataType.INT, unique=True),
        SchemaField("name", DataType.STR),
        SchemaField("email", DataType.ENCRYPTED_STR),
        SchemaField("salary", DataType.ENCRYPTED_FLOAT),
        SchemaField("department", DataType.STR),
        SchemaField("status", DataType.STR, choices=["active", "inactive"])
    ])

@pytest.fixture
def test_db(test_schema):
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        db = Database(db_path, keypair=generate_keypair())
        table = db.create_table("employees", test_schema)
        yield db, table

@pytest.fixture
def auth_manager():
    manager = AuthManager()
    
    # Add permissions
    rbac = RBAC()
    rbac.add_permission("read_data")
    rbac.add_permission("write_data")
    rbac.add_permission("manage_users")
    
    # Add roles
    rbac.add_role("admin", ["read_data", "write_data", "manage_users"])
    rbac.add_role("user", ["read_data"])
    
    # Add users
    manager.add_user("admin", "admin123", ["admin"])
    manager.add_user("user", "user123", ["user"])
    
    return manager

def test_complete_workflow(test_db, auth_manager):
    """Test complete workflow with all features"""
    db, table = test_db
    
    # 1. Authentication
    admin_token = auth_manager.authenticate("admin", "admin123")
    user_token = auth_manager.authenticate("user", "user123")
    
    assert admin_token is not None
    assert user_token is not None
    
    # 2. Authorization
    assert auth_manager.has_role(admin_token, "admin")
    assert not auth_manager.has_role(user_token, "admin")
    
    # 3. Data Operations
    # Insert data
    table.insert({
        "id": 1,
        "name": "John Doe",
        "email": "john@example.com",
        "salary": 50000.0,
        "department": "IT",
        "status": "active"
    })
    
    # Create indexes
    table.create_index("dept_idx", "department")
    table.create_compound_index("dept_status_idx", ["department", "status"])
    
    # Query data
    query = Query()\
        .filter("department", Operator.EQ, "IT")\
        .filter("status", Operator.EQ, "active")
    
    results = table.select(query)
    assert len(results) == 1
    assert results[0]["name"] == "John Doe"
    
    # Update data
    update_query = Query().filter("id", Operator.EQ, 1)
    table.update(update_query, {"salary": 55000.0})
    
    # Verify update
    updated = table.select(update_query)
    assert len(updated) == 1
    assert updated[0]["salary"] == 55000.0
    
    # Aggregation
    stats = table.aggregate(
        group_by=["department"],
        aggregations={
            "salary": ["avg", "sum"],
            "status": ["count"]
        }
    )
    assert len(stats) == 1
    assert "salary_avg" in stats[0]
    
    # 4. Data Integrity
    # Try to insert invalid data
    with pytest.raises(ValtDBError):
        table.insert({
            "id": 2,
            "name": "Invalid",
            "status": "unknown"  # Invalid choice
        })
    
    # Try to insert duplicate unique field
    with pytest.raises(ValtDBError):
        table.insert({
            "id": 1,  # Duplicate ID
            "name": "Another John",
            "status": "active"
        })
    
    # 5. Token Management
    # Invalidate token
    auth_manager.invalidate_token(user_token)
    assert auth_manager.verify_token(user_token) is None

def test_remote_operations(test_db):
    """Test remote database operations"""
    db, table = test_db
    
    # Setup SSH config (using mock for testing)
    ssh_config = SSHConfig(
        hostname="localhost",
        username="test",
        password="test"
    )
    
    with RemoteDatabase(ssh_config, db.path) as remote_db:
        # Execute query
        output, error, status = remote_db.execute_query(
            'SELECT * FROM employees WHERE department = "IT"'
        )
        assert status == 0
        
        # Backup database
        with tempfile.NamedTemporaryFile() as tmp:
            remote_db.backup(tmp.name)
            assert os.path.exists(tmp.name)
            
            # Restore database
            remote_db.restore(tmp.name)

def test_error_handling(test_db, auth_manager):
    """Test error handling"""
    db, table = test_db
    
    # 1. Authentication errors
    assert auth_manager.authenticate("admin", "wrongpass") is None
    assert auth_manager.authenticate("nonexistent", "pass") is None
    
    # 2. Authorization errors
    user_token = auth_manager.authenticate("user", "user123")
    assert not auth_manager.has_role(user_token, "admin")
    
    # 3. Data validation errors
    with pytest.raises(ValtDBError):
        table.insert({
            "id": "not_an_integer",  # Wrong type
            "name": 123,  # Wrong type
            "status": "invalid"  # Invalid choice
        })
    
    # 4. Query errors
    with pytest.raises(ValtDBError):
        table.select(Query().filter("nonexistent", Operator.EQ, "value"))
    
    # 5. Index errors
    with pytest.raises(ValtDBError):
        table.create_index("duplicate_idx", "department")
        table.create_index("duplicate_idx", "department")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
