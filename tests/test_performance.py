"""
Performance tests for ValtDB
"""
import pytest
import time
import random
import string
from valtdb import Database
from valtdb.schema import Schema, SchemaField, DataType
from valtdb.query import Query, Operator
from valtdb.ssh import SSHConfig, RemoteDatabase
from valtdb.auth import AuthManager, RBAC

def generate_random_string(length=10):
    """Generate random string"""
    return ''.join(random.choices(string.ascii_letters, k=length))

def generate_test_data(n=1000):
    """Generate test data"""
    return [
        {
            "id": i,
            "name": generate_random_string(),
            "age": random.randint(18, 80),
            "salary": random.uniform(30000, 120000),
            "department": random.choice(["IT", "HR", "Sales", "Marketing"]),
            "status": random.choice(["active", "inactive"])
        }
        for i in range(n)
    ]

@pytest.fixture
def test_db():
    """Create test database"""
    schema = Schema([
        SchemaField("id", DataType.INT, unique=True),
        SchemaField("name", DataType.STR),
        SchemaField("age", DataType.INT),
        SchemaField("salary", DataType.FLOAT),
        SchemaField("department", DataType.STR),
        SchemaField("status", DataType.STR)
    ])
    
    db = Database("test_db")
    table = db.create_table("employees", schema)
    return table

def benchmark(func):
    """Benchmark decorator"""
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        duration = end_time - start_time
        print(f"{func.__name__}: {duration:.4f} seconds")
        return result, duration
    return wrapper

@benchmark
def test_bulk_insert(table, data):
    """Test bulk insert performance"""
    for row in data:
        table.insert(row)

@benchmark
def test_simple_query(table):
    """Test simple query performance"""
    return table.select(Query().filter("department", Operator.EQ, "IT"))

@benchmark
def test_complex_query(table):
    """Test complex query performance"""
    return table.select(
        Query()
        .filter("age", Operator.GT, 30)
        .filter("salary", Operator.GT, 50000)
        .filter("status", Operator.EQ, "active")
        .sort("salary", ascending=False)
        .limit(100)
    )

@benchmark
def test_aggregation(table):
    """Test aggregation performance"""
    return table.aggregate(
        group_by=["department"],
        aggregations={
            "salary": ["avg", "min", "max"],
            "age": ["avg", "count"]
        }
    )

@benchmark
def test_index_query(table):
    """Test indexed query performance"""
    table.create_index("salary_idx", "salary")
    return table.select(Query().filter("salary", Operator.GT, 50000))

@benchmark
def test_compound_index_query(table):
    """Test compound index query performance"""
    table.create_compound_index("dept_salary_idx", ["department", "salary"])
    return table.select(
        Query()
        .filter("department", Operator.EQ, "IT")
        .filter("salary", Operator.GT, 50000)
    )

def test_performance_suite(test_db):
    """Run complete performance test suite"""
    print("\nRunning performance tests...")
    
    # Generate test data
    data = generate_test_data(10000)
    
    # Run tests
    insert_result, insert_time = test_bulk_insert(test_db, data)
    simple_result, simple_time = test_simple_query(test_db)
    complex_result, complex_time = test_complex_query(test_db)
    agg_result, agg_time = test_aggregation(test_db)
    index_result, index_time = test_index_query(test_db)
    compound_result, compound_time = test_compound_index_query(test_db)
    
    # Print summary
    print("\nPerformance Summary:")
    print(f"{'Operation':<25} {'Time (seconds)':<15} {'Records':<10}")
    print("-" * 50)
    print(f"{'Bulk Insert (10k)':<25} {insert_time:<15.4f} {10000:<10}")
    print(f"{'Simple Query':<25} {simple_time:<15.4f} {len(simple_result[0]):<10}")
    print(f"{'Complex Query':<25} {complex_time:<15.4f} {len(complex_result[0]):<10}")
    print(f"{'Aggregation':<25} {agg_time:<15.4f} {len(agg_result[0]):<10}")
    print(f"{'Indexed Query':<25} {index_time:<15.4f} {len(index_result[0]):<10}")
    print(f"{'Compound Index Query':<25} {compound_time:<15.4f} {len(compound_result[0]):<10}")

@pytest.mark.benchmark
def test_encryption_performance(test_db):
    """Test encryption performance"""
    print("\nTesting encryption performance...")
    
    # Create schema with encrypted fields
    schema = Schema([
        SchemaField("id", DataType.INT),
        SchemaField("name", DataType.ENCRYPTED_STR),
        SchemaField("salary", DataType.ENCRYPTED_FLOAT)
    ])
    
    db = Database("encrypted_db", keypair=generate_keypair())
    table = db.create_table("secure_employees", schema)
    
    # Test encrypted operations
    @benchmark
    def test_encrypted_insert():
        return table.insert({
            "id": 1,
            "name": "John Doe",
            "salary": 50000.0
        })
    
    @benchmark
    def test_encrypted_query():
        return table.select(Query().filter("id", Operator.EQ, 1))
    
    insert_result, insert_time = test_encrypted_insert()
    query_result, query_time = test_encrypted_query()
    
    print("\nEncryption Performance:")
    print(f"{'Operation':<25} {'Time (seconds)':<15}")
    print("-" * 40)
    print(f"{'Encrypted Insert':<25} {insert_time:<15.4f}")
    print(f"{'Encrypted Query':<25} {query_time:<15.4f}")

@pytest.mark.benchmark
def test_remote_performance():
    """Test remote database performance"""
    print("\nTesting remote database performance...")
    
    # Setup SSH config (using mock for testing)
    ssh_config = SSHConfig(
        hostname="localhost",
        username="test",
        password="test"
    )
    
    @benchmark
    def test_remote_connection():
        with RemoteDatabase(ssh_config, "/tmp/test.db") as remote_db:
            return remote_db.execute_query("SELECT * FROM test")
    
    conn_result, conn_time = test_remote_connection()
    
    print("\nRemote Operation Performance:")
    print(f"{'Operation':<25} {'Time (seconds)':<15}")
    print("-" * 40)
    print(f"{'Remote Query':<25} {conn_time:<15.4f}")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
