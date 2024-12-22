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
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union, cast, Type

from .auth import RBAC, AuthManager
from .crypto.encryption import EncryptionAlgorithm, EncryptionManager, HashAlgorithm, KeyPair
from .database import Database
from .exceptions import ValtDBError
from .schema import DataType, Schema, SchemaField
from .ssh import RemoteDatabase, SSHConfig
from .query import Query, Operator
from .table import Table

logger = logging.getLogger(__name__)


class SortOrder(Enum):
    ASC = "ASC"
    DESC = "DESC"


class QueryBuilder:
    """Enhanced query builder with intuitive methods"""

    def __init__(self, table: 'Table'):
        self.table = table
        self.query = Query()
        self._selected_fields: set = set()
        self._group_by: List[str] = []
        self._order_by: List[tuple] = []
        self._limit: Optional[int] = None
        self._offset: Optional[int] = None
        self._joins: List[Dict[str, Any]] = []

    def select(self, *fields) -> "QueryBuilder":
        """Select specific fields"""
        self._selected_fields.update(fields)
        return self

    def where(self, **conditions) -> "QueryBuilder":
        """Add WHERE conditions"""
        for field, value in conditions.items():
            if isinstance(value, tuple):
                operator, val = value
                self.query.filter(field, Operator(operator), val)
            else:
                self.query.filter(field, Operator.EQUALS, value)
        return self

    def where_in(self, field: str, values: List[Any]) -> "QueryBuilder":
        """Add WHERE IN condition"""
        self.query.filter(field, Operator.IN, values)
        return self

    def where_not_in(self, field: str, values: List[Any]) -> "QueryBuilder":
        """Add WHERE NOT IN condition"""
        self.query.filter(field, Operator.NOT_IN, values)
        return self

    def where_between(self, field: str, start: Any, end: Any) -> "QueryBuilder":
        """Add WHERE BETWEEN condition"""
        self.query.filter(field, Operator.GREATER_THAN, start)
        self.query.filter(field, Operator.LESS_THAN, end)
        return self

    def where_null(self, field: str) -> "QueryBuilder":
        """Add WHERE IS NULL condition"""
        self.query.filter(field, Operator.EQUALS, None)
        return self

    def where_not_null(self, field: str) -> "QueryBuilder":
        """Add WHERE IS NOT NULL condition"""
        self.query.filter(field, Operator.NOT_EQUALS, None)
        return self

    def where_like(self, field: str, pattern: str) -> "QueryBuilder":
        """Add WHERE LIKE condition"""
        self.query.filter(field, Operator.CONTAINS, pattern)
        return self

    def or_where(self, **conditions) -> "QueryBuilder":
        """Add OR WHERE conditions"""
        for field, value in conditions.items():
            if isinstance(value, tuple):
                operator, val = value
                self.query.or_filter(field, Operator(operator), val)
            else:
                self.query.or_filter(field, Operator.EQUALS, value)
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
        self._joins.append({
            "type": "JOIN",
            "table": table,
            "on": on
        })
        return self

    def left_join(self, table: str, on: Dict[str, str]) -> "QueryBuilder":
        """Add LEFT JOIN clause"""
        self._joins.append({
            "type": "LEFT JOIN",
            "table": table,
            "on": on
        })
        return self

    def get(self) -> List[Dict[str, Any]]:
        """Execute query and return results"""
        return self.table.select(self.query)

    def update(self, data: Dict[str, Any]) -> None:
        """Update records"""
        self.table.update(self.query, data)
        return None

    def delete(self) -> None:
        """Delete records"""
        self.table.delete(self.query)
        return None

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
        return self.table.count(self.query)


class ValtDB:
    """Main ValtDB interface."""
    
    def __init__(self, path: str):
        """Initialize ValtDB instance."""
        self.base_path = Path(path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        self.current_db: Optional[Database] = None
        self.current_table: Optional['Table'] = None
        self._encryption: Optional[EncryptionManager] = None

    def generate_private_key(self, password: str) -> Any:
        """Generate a private key from a password."""
        # Placeholder implementation
        return password.encode()

    def derive_public_key(self, private_key: Any) -> Any:
        """Derive a public key from a private key."""
        # Placeholder implementation
        return private_key

    def connect(self, password: Optional[str] = None) -> None:
        """Connect to database."""
        if password:
            private_key = self.generate_private_key(password)
            public_key = self.derive_public_key(private_key)
            self._encryption = EncryptionManager(KeyPair(private_key, public_key))
        self.current_db = Database(str(self.base_path), encryption_manager=self._encryption)
        return None

    def close(self) -> None:
        """Close database connection."""
        if self.current_db:
            if hasattr(self.current_db, 'close'):
                self.current_db.close()
            self.current_db = None
            self.current_table = None
        return None

    def create_table(self, name: str, schema: Dict[str, Any]) -> None:
        """Create a new table."""
        if not self.current_db:
            raise ValtDBError("Not connected to database")
        if hasattr(self.current_db, 'create_table'):
            self.current_db.create_table(name, schema)
        return None  # Explicitly return None if conditions are not met

    def get_table(self, name: str) -> 'Table':
        """Get table by name."""
        if not self.current_db:
            raise ValtDBError("Not connected to database")
        if hasattr(self.current_db, 'get_table'):
            table = self.current_db.get_table(name)
            self.current_table = table
            return table
        raise ValtDBError("Database does not support table operations")

    def list_tables(self) -> List[str]:
        """List all tables."""
        if not self.current_db:
            raise ValtDBError("Not connected to database")
        if hasattr(self.current_db, 'list_tables'):
            return self.current_db.list_tables()
        return []  

    def insert(self, table_name: str, data: Dict[str, Any]) -> None:
        """Insert data into table."""
        if not self.current_db:
            raise ValtDBError("Not connected to database")
        table = self.get_table(table_name)
        table.insert(data)
        return None  

    def update(self, table_name: str, query: Dict[str, Any], updates: Dict[str, Any]) -> None:
        """Update records in table."""
        if not self.current_db:
            raise ValtDBError("Not connected to database")
        table = self.get_table(table_name)
        query_obj = Query.from_dict(query)
        table.update(query_obj, updates)
        return None  

    def select(self, table_name: str, query: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Select records from table."""
        if not self.current_db:
            raise ValtDBError("Not connected to database")
        table = self.get_table(table_name)
        query_obj = Query.from_dict(query) if query else None
        return table.select(query_obj)

    def delete(self, table_name: str, query: Dict[str, Any]) -> None:
        """Delete records from table."""
        if not self.current_db:
            raise ValtDBError("Not connected to database")
        table = self.get_table(table_name)
        query_obj = Query.from_dict(query)
        table.delete(query_obj)
        return None  

    def count(self, table_name: str, query: Optional[Dict[str, Any]] = None) -> int:
        """Count records in table."""
        if not self.current_db:
            raise ValtDBError("Not connected to database")
        table = self.get_table(table_name)
        query_obj = Query.from_dict(query) if query else None
        return table.count(query_obj)

    def backup(self, path: str) -> None:
        """Backup database."""
        if not self.current_db:
            raise ValtDBError("Not connected to database")
        if hasattr(self.current_db, 'backup'):
            self.current_db.backup(path)
        else:
            raise ValtDBError("Database does not support backup")
        return None  

    def restore(self, backup_file: str) -> None:
        """Restore database from backup."""
        if not os.path.exists(backup_file):
            raise ValtDBError(f"Backup file not found: {backup_file}")
        if not self.current_db:
            raise ValtDBError("Not connected to database")
        if hasattr(self.current_db, 'restore'):
            self.current_db.restore(backup_file)
        else:
            raise ValtDBError("Database does not support restore")
        return None  

    def __enter__(self) -> 'ValtDB':
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
        return None  
