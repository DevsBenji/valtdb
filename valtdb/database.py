"""Database management for ValtDB."""

import json
import os
from typing import Any, Dict, List, Optional, Union

from .crypto.encryption import EncryptionManager, KeyPair
from .exceptions import ValtDBError
from .schema import Schema, SchemaField  # Import Schema and SchemaField classes
from .table import Table


class Database:
    """Manages database operations and tables."""

    def __init__(self, path: str, encryption_manager: Optional[EncryptionManager] = None):
        """
        Initialize database.

        Args:
            path: Path to the database file or directory
            encryption_manager: Optional encryption manager
        """
        self.path = os.path.abspath(path)
        self._encryption_manager = encryption_manager
        self._tables: Dict[str, Table] = {}

        # Create database directory if it doesn't exist
        os.makedirs(self.path, exist_ok=True)

        # Load existing tables
        self._load_tables()

    def _load_tables(self):
        """Load existing tables from database directory."""
        if os.path.isdir(self.path):
            for filename in os.listdir(self.path):
                if filename.endswith(".json"):
                    table_name = os.path.splitext(filename)[0]
                    table_path = os.path.join(self.path, filename)

                    try:
                        with open(table_path, "r") as f:
                            table_data = json.load(f)

                        # If encryption is used, decrypt table data
                        if self._encryption_manager:
                            table_data = self._encryption_manager.decrypt(table_data)

                        self._tables[table_name] = Table(
                            name=table_name,
                            table_data=table_data,
                            keypair=(
                                self._encryption_manager.keypair
                                if self._encryption_manager
                                else None
                            ),
                        )
                    except Exception as e:
                        raise ValtDBError(f"Failed to load table {table_name}: {str(e)}")

    def table(self, name: str, schema_dict: Optional[Dict[str, str]] = None) -> "Table":
        """
        Create or get a table.

        Args:
            name: Name of the table
            schema_dict: Optional dictionary of field names and types

        Returns:
            Table instance
        """
        # If table exists, return it
        if name in self._tables:
            return self._tables[name]

        # If no schema provided, create an empty table
        if schema_dict is None:
            schema_dict = {}

        # Convert simple type strings to schema dictionary
        full_schema_dict = {}
        for field_name, field_type in schema_dict.items():
            full_schema_dict[field_name] = {
                "type": field_type,
                "required": False,
                "unique": False,
                "encrypted": False,
            }

        # Create table data structure
        table_data = {"schema": full_schema_dict, "data": []}

        # Create and store the table
        self._tables[name] = Table(
            name=name,
            table_data=table_data,
            keypair=(
                self._encryption_manager.generate_keypair() if self._encryption_manager else None
            ),
        )

        return self._tables[name]

    def create_table(
        self, name: str, schema: Union[Dict[str, str], Schema, Dict[str, Any]]
    ) -> Table:
        """
        Create a new table.

        Args:
            name: Name of the table
            schema: Schema for the table (can be a dictionary, Schema object, or SchemaField)

        Returns:
            Table instance
        """
        if name in self._tables:
            raise ValtDBError(f"Table {name} already exists")

        # Convert schema to dictionary of field types
        if isinstance(schema, Schema):
            schema_dict = {field.name: field.field_type.value for field in schema.fields}
        elif isinstance(schema, dict):
            schema_dict = {}
            for field_name, field_def in schema.items():
                # Handle different schema definition formats
                if isinstance(field_def, str):
                    # Simple type definition like {"name": "str"}
                    schema_dict[field_name] = field_def
                elif isinstance(field_def, dict):
                    # More complex definition like {"name": {"type": "str", "unique": True}}
                    schema_dict[field_name] = field_def.get(
                        "type", field_def.get("field_type", "str")
                    )
                else:
                    raise ValtDBError(f"Invalid schema definition for field {field_name}")
        else:
            raise ValtDBError(f"Invalid schema type: {type(schema)}")

        return self.table(name, schema_dict)

    def save(self):
        """Save all tables to disk."""
        for name, table in self._tables.items():
            table_path = os.path.join(self.path, f"{name}.json")

            # Prepare table data for saving
            table_data = {"schema": table.schema.to_dict(), "data": table._data}

            # If encryption is used, encrypt table data
            if self._encryption_manager:
                table_data = self._encryption_manager.encrypt(table_data)

            with open(table_path, "w") as f:
                json.dump(table_data, f)

    def close(self):
        """Close database and save changes."""
        self.save()
        self._tables.clear()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

    def list_tables(self) -> List[str]:
        """List all tables in database.

        Returns:
            List[str]: List of table names
        """
        return list(self._tables.keys())

    def drop_table(self, name: str) -> None:
        """Drop table by name.

        Args:
            name: Name of the table

        Raises:
            ValtDBError: If the table does not exist
        """
        if name not in self._tables:
            raise ValtDBError(f"Table {name} does not exist")
        del self._tables[name]
        table_path = os.path.join(self.path, f"{name}.json")
        os.remove(table_path)

    def get_table(self, name: str) -> Table:
        """Get table by name.

        Args:
            name: Name of the table

        Returns:
            Table: The table with the specified name

        Raises:
            ValtDBError: If the table does not exist
        """
        if name not in self._tables:
            raise ValtDBError(f"Table {name} does not exist")
        return self._tables[name]


class Table:
    """Represents a table in the database."""

    def __init__(self, name: str, table_data: Dict[str, Any], keypair: Optional[KeyPair] = None):
        """
        Initialize table.

        Args:
            name: Name of the table
            table_data: Table data (schema and records)
            keypair: Optional keypair for encryption
        """
        self.name = name
        self._data = table_data["data"]
        self.schema = Schema.from_dict(table_data["schema"])
        self.keypair = keypair

    def all(self):
        """Return all records in the table"""
        return list(self._data)

    # ... rest of the Table class methods ...
