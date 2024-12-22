"""Database management for ValtDB."""

import json
import os
from typing import Any, Dict, List, Optional, Union

from .crypto.encryption import EncryptionManager, KeyPair
from .exceptions import ValtDBError
from .schema import Schema  # Import Schema class
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
        self.encryption_manager = encryption_manager
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
                        if self.encryption_manager:
                            table_data = self.encryption_manager.decrypt(table_data)

                        self._tables[table_name] = Table(
                            name=table_name,
                            table_data=table_data,
                            keypair=(
                                self.encryption_manager.keypair if self.encryption_manager else None
                            ),
                        )
                    except Exception as e:
                        raise ValtDBError(f"Failed to load table {table_name}: {str(e)}")

    def table(self, name: str, schema: Optional[Dict[str, str]] = None) -> Table:
        """
        Get or create a table.

        Args:
            name: Name of the table
            schema: Optional schema for the table

        Returns:
            Table instance
        """
        if name not in self._tables:
            if schema is None:
                raise ValtDBError(f"Table {name} does not exist and no schema provided")

            table_data = {"schema": schema, "data": []}

            # If encryption is used, encrypt table data
            if self.encryption_manager:
                table_data = self.encryption_manager.encrypt(table_data)

            # Save table to file
            table_path = os.path.join(self.path, f"{name}.json")
            with open(table_path, "w") as f:
                json.dump(table_data, f)

            self._tables[name] = Table(
                name=name,
                table_data=table_data,
                keypair=self.encryption_manager.keypair if self.encryption_manager else None,
            )

        return self._tables[name]

    def create_table(self, name: str, schema: Union[Dict[str, str], Schema]) -> Table:
        """
        Create a new table.

        Args:
            name: Name of the table
            schema: Schema for the table

        Returns:
            Table instance
        """
        if name in self._tables:
            raise ValtDBError(f"Table {name} already exists")

        # Convert schema to dictionary if it's a Schema object
        if isinstance(schema, Schema):
            schema_dict = {field.name: field.field_type.value for field in schema.fields}
        else:
            schema_dict = schema

        return self.table(name, schema_dict)

    def save(self):
        """Save all tables to disk."""
        for name, table in self._tables.items():
            table_path = os.path.join(self.path, f"{name}.json")

            # Prepare table data for saving
            table_data = {"schema": table.schema.to_dict(), "data": table._data}

            # If encryption is used, encrypt table data
            if self.encryption_manager:
                table_data = self.encryption_manager.encrypt(table_data)

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
