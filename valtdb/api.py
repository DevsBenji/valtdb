"""
ValtDB API Module - Enhanced Query Interface
"""

import json
import logging
import os
import shutil
from datetime import date, datetime
from enum import Enum
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from .auth import RBAC, AuthManager
from .crypto.encryption import EncryptionAlgorithm, EncryptionManager, HashAlgorithm
from .database import Database
from .exceptions import ValtDBError
from .query import Operator, Query
from .schema import DataType, Schema, SchemaField
from .ssh import RemoteDatabase, SSHConfig

logger = logging.getLogger(__name__)


class SortOrder(Enum):
    ASC = "ASC"
    DESC = "DESC"


class QueryBuilder:
    """Enhanced query builder with intuitive methods"""

    def __init__(self, table):
        self._table = table
        self._query = Query()
        self._selected_fields = set()
        self._group_by = []
        self._order_by = []
        self._limit = None
        self._offset = None
        self._joins = []

    def select(self, *fields) -> "QueryBuilder":
        """Select specific fields"""
        self._selected_fields.update(fields)
        return self

    def where(self, **conditions) -> "QueryBuilder":
        """Add WHERE conditions"""
        for field, value in conditions.items():
            if isinstance(value, tuple):
                operator, val = value
                self._query.filter(field, Operator[operator], val)
            else:
                self._query.filter(field, Operator.EQ, value)
        return self

    def where_in(self, field: str, values: List[Any]) -> "QueryBuilder":
        """Add WHERE IN condition"""
        self._query.filter(field, Operator.IN, values)
        return self

    def where_not_in(self, field: str, values: List[Any]) -> "QueryBuilder":
        """Add WHERE NOT IN condition"""
        self._query.filter(field, Operator.NOT_IN, values)
        return self

    def where_between(self, field: str, start: Any, end: Any) -> "QueryBuilder":
        """Add WHERE BETWEEN condition"""
        self._query.filter(field, Operator.BETWEEN, (start, end))
        return self

    def where_null(self, field: str) -> "QueryBuilder":
        """Add WHERE IS NULL condition"""
        self._query.filter(field, Operator.IS_NULL, None)
        return self

    def where_not_null(self, field: str) -> "QueryBuilder":
        """Add WHERE IS NOT NULL condition"""
        self._query.filter(field, Operator.IS_NOT_NULL, None)
        return self

    def where_like(self, field: str, pattern: str) -> "QueryBuilder":
        """Add WHERE LIKE condition"""
        self._query.filter(field, Operator.LIKE, pattern)
        return self

    def or_where(self, **conditions) -> "QueryBuilder":
        """Add OR WHERE conditions"""
        for field, value in conditions.items():
            if isinstance(value, tuple):
                operator, val = value
                self._query.or_filter(field, Operator[operator], val)
            else:
                self._query.or_filter(field, Operator.EQ, value)
        return self

    def group_by(self, *fields) -> "QueryBuilder":
        """Add GROUP BY clause"""
        self._group_by.extend(fields)
        return self

    def order_by(self, field: str, order: SortOrder = SortOrder.ASC) -> "QueryBuilder":
        """Add ORDER BY clause"""
        self._order_by.append((field, order))
        return self

    def limit(self, limit: int) -> "QueryBuilder":
        """Add LIMIT clause"""
        self._limit = limit
        return self

    def offset(self, offset: int) -> "QueryBuilder":
        """Add OFFSET clause"""
        self._offset = offset
        return self

    def join(self, table: str, on: Dict[str, str]) -> "QueryBuilder":
        """Add JOIN clause"""
        self._joins.append(("JOIN", table, on))
        return self

    def left_join(self, table: str, on: Dict[str, str]) -> "QueryBuilder":
        """Add LEFT JOIN clause"""
        self._joins.append(("LEFT JOIN", table, on))
        return self

    def get(self) -> List[Dict[str, Any]]:
        """Execute query and return results"""
        return self._table.select(self._query)

    def first(self) -> Optional[Dict[str, Any]]:
        """Get first result"""
        self.limit(1)
        results = self.get()
        return results[0] if results else None

    def exists(self) -> bool:
        """Check if any records exist"""
        return bool(self.first())

    def count(self) -> int:
        """Get count of records"""
        return len(self.get())

    def sum(self, field: str) -> Union[int, float]:
        """Get sum of field"""
        results = self.get()
        return sum(r[field] for r in results)

    def avg(self, field: str) -> float:
        """Get average of field"""
        results = self.get()
        return sum(r[field] for r in results) / len(results) if results else 0

    def min(self, field: str) -> Any:
        """Get minimum value of field"""
        results = self.get()
        return min(r[field] for r in results) if results else None

    def max(self, field: str) -> Any:
        """Get maximum value of field"""
        results = self.get()
        return max(r[field] for r in results) if results else None

    def pluck(self, field: str) -> List[Any]:
        """Get list of values for a field"""
        results = self.get()
        return [r[field] for r in results]

    def chunk(self, size: int, callback: Callable[[List[Dict[str, Any]]], None]):
        """Process results in chunks"""
        offset = 0
        while True:
            results = self.limit(size).offset(offset).get()
            if not results:
                break
            callback(results)
            offset += size

    def paginate(
        self, page: int = 1, per_page: int = 10
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Get paginated results"""
        total = self.count()

        results = self.limit(per_page).offset((page - 1) * per_page).get()

        return results, {
            "total": total,
            "per_page": per_page,
            "current_page": page,
            "last_page": (total + per_page - 1) // per_page,
            "from": (page - 1) * per_page + 1,
            "to": (page - 1) * per_page + len(results),
        }

    def get(self):
        """Execute the query and return results"""
        return self._table.all()

    def __len__(self):
        """Return the number of results"""
        return len(self.get())


class Table:
    """Enhanced table interface"""

    def __init__(self, db_table, name: str):
        self._table = db_table
        self.name = name

    def query(self) -> QueryBuilder:
        """Create new query builder"""
        return QueryBuilder(self._table)

    def all(self) -> List[Dict[str, Any]]:
        """Get all records"""
        return self.query().get()

    def find(self, id: Any) -> Optional[Dict[str, Any]]:
        """Find record by ID"""
        return self.query().where(id=id).first()

    def find_or_fail(self, id: Any) -> Dict[str, Any]:
        """Find record by ID or raise error"""
        result = self.find(id)
        if not result:
            raise ValtDBError(f"Record with id {id} not found")
        return result

    def first_or_create(
        self, search: Dict[str, Any], create: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Get first record or create it"""
        result = self.query().where(**search).first()
        if result:
            return result

        data = {**search, **(create or {})}
        self.insert(data)
        return self.query().where(**search).first()

    def update_or_create(self, search: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
        """Update record or create it"""
        result = self.query().where(**search).first()
        if result:
            self.query().where(**search).update(update)
            return self.query().where(**search).first()

        data = {**search, **update}
        self.insert(data)
        return self.query().where(**search).first()

    def insert(
        self, data: Union[Dict[str, Any], List[Dict[str, Any]]]
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """Insert record(s)"""
        if isinstance(data, list):
            for record in data:
                self._table.insert(record)
            return data
        else:
            self._table.insert(data)
            return data

    def insert_get_id(self, data: Dict[str, Any]) -> Any:
        """Insert record and return ID"""
        self.insert(data)
        return self.query().where(**data).first()["id"]

    def bulk_insert(self, data: List[Dict[str, Any]], chunk_size: int = 1000):
        """Insert records in chunks"""
        for i in range(0, len(data), chunk_size):
            chunk = data[i : i + chunk_size]
            self.insert(chunk)

    def update(self, data: Dict[str, Any]) -> int:
        """Update records"""
        return self._table.update(self._query, data)

    def delete(self) -> int:
        """Delete records"""
        return self._table.delete(self._query)

    def truncate(self):
        """Delete all records"""
        self.query().delete()

    def select(self, *fields):
        """Select records from the table"""
        query_builder = self.query()
        if fields:
            query_builder.select(*fields)
        return query_builder.get()

    def where(self, **conditions):
        """Filter records by conditions"""
        query_builder = self.query()
        query_builder.where(**conditions)
        return query_builder


class ValtDB:
    """Main ValtDB interface with enhanced features"""

    def __init__(self, path: str):
        self.base_path = Path(path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        self.current_db = None
        self.current_table = None
        self._encryption = None

    def db(self, name: str, encryption: Optional[Dict] = None) -> "ValtDB":
        """Select or create database"""
        db_path = self.base_path / name

        if not db_path.exists():
            if encryption:
                self._encryption = EncryptionManager(
                    encryption_algorithm=EncryptionAlgorithm[encryption.get("algorithm", "AES")],
                    hash_algorithm=HashAlgorithm[encryption.get("hash_algorithm", "SHA256")],
                )
            self.current_db = Database(str(db_path), encryption_manager=self._encryption)
        else:
            self.current_db = Database(str(db_path))

        return self

    def table(self, name: str, schema: Optional[Dict] = None) -> Table:
        """Select or create table"""
        if not self.current_db:
            raise ValtDBError("No database selected")

        if schema:
            # Convert schema to a dictionary of field types
            schema_dict = {}
            for name, config in schema.items():
                if isinstance(config, str):
                    schema_dict[name] = config
                elif isinstance(config, dict):
                    schema_dict[name] = config.get('type', config.get('field_type', 'str'))
        
            table = self.current_db.table(name, schema_dict)
        else:
            table = self.current_db.get_table(name)

        self.current_table = Table(table, name)
        return self.current_table

    def _create_schema(self, schema_dict: Dict[str, Any]) -> Schema:
        """Create schema from dictionary"""
        fields = []
        for name, config in schema_dict.items():
            if isinstance(config, str):
                field = SchemaField(name=name, data_type=DataType[config.upper()])
            else:
                field = SchemaField(
                    name=name,
                    data_type=DataType[config["type"].upper()],
                    required=config.get("required", False),
                    unique=config.get("unique", False),
                    encrypted=config.get("encrypted", False),
                    default=config.get("default"),
                    choices=config.get("choices"),
                )
            fields.append(field)
        return Schema(fields)

    def tables(self):
        """Get list of tables in the current database"""
        if not self.current_db:
            raise ValtDBError("No database selected")
        return list(self.current_db._tables.keys())

    def transaction(self):
        """Start database transaction"""
        return self.current_db.transaction()

    def backup(self, path: str) -> str:
        """Backup database"""
        if not self.current_db:
            raise ValtDBError("No database selected")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = f"{path}/backup_{timestamp}.db"
        self.current_db.backup(backup_file)
        return backup_file

    def restore(self, backup_file: str) -> "ValtDB":
        """Restore database from backup"""
        if not self.current_db:
            raise ValtDBError("No database selected")

        self.current_db.restore(backup_file)
        return self

    def execute(self, query: str, params: Optional[Dict] = None) -> List[Dict[str, Any]]:
        """Execute raw query"""
        if not self.current_db:
            raise ValtDBError("No database selected")

        return self.current_db.execute_query(query, params)


# Usage Examples:
"""
# Initialize database
db = ValtDB("./data")

# Create users table
users = db.db("myapp").table("users", {
    "id": "int",
    "name": "str",
    "email": {"type": "str", "unique": True},
    "age": "int",
    "status": {"type": "str", "choices": ["active", "inactive"]}
})

# Complex queries
active_adult_users = users.query()\\
    .select("name", "email")\\
    .where(status="active")\\
    .where_between("age", 18, 65)\\
    .where_not_null("email")\\
    .order_by("name", SortOrder.ASC)\\
    .get()

# Aggregations
total_users = users.query().count()
avg_age = users.query().where(status="active").avg("age")
newest_users = users.query().order_by("created_at", SortOrder.DESC).limit(5).get()

# Find or create
user = users.first_or_create(
    {"email": "john@example.com"},
    {"name": "John Doe", "status": "active"}
)

# Bulk operations
users.bulk_insert([
    {"name": "User 1", "email": "user1@example.com"},
    {"name": "User 2", "email": "user2@example.com"}
], chunk_size=100)

# Process in chunks
users.query().chunk(100, lambda chunk: print(f"Processing {len(chunk)} users"))

# Transactions
with db.transaction():
    users.insert({"name": "Test User"})
    posts.insert({"user_id": 1, "title": "Test Post"})

# Advanced queries
active_users_with_posts = users.query()\\
    .select("users.*", "posts.title")\\
    .join("posts", {"users.id": "posts.user_id"})\\
    .where(status="active")\\
    .where_exists("posts")\\
    .group_by("users.id")\\
    .having("post_count", ("GT", 5))\\
    .get()
"""
