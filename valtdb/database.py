"""Database management for ValtDB."""

import json
import os
from typing import Any, Dict, List, Optional, Union, Type, cast
from datetime import datetime
from enum import Enum, auto

from .crypto.encryption import EncryptionManager, KeyPair, generate_keypair
from .exceptions import ValtDBError
from .schema import Schema, SchemaField, DataType  # Import Schema and SchemaField classes
from .table import Table


class Database:
    """Manages database operations and tables."""

    def __init__(
        self,
        name: str,
        path: Optional[str] = None,
        encryption_manager: Optional[EncryptionManager] = None,
        keypair: Optional[KeyPair] = None,
    ):
        """
        Initialize database.

        Args:
            name: Name of the database
            path: Path to the database file or directory
            encryption_manager: Optional encryption manager
            keypair: Optional keypair for encryption
        """
        # Use path or create a default path
        if path is None:
            path = os.path.join(os.getcwd(), name)

        self.path = os.path.abspath(path)
        self.name = name

        # Use provided encryption manager or create one if keypair is provided
        self._encryption_manager = encryption_manager
        if keypair and not encryption_manager:
            self._encryption_manager = EncryptionManager(keypair)

        self._tables: Dict[str, Table] = {}

        # Create database directory if it doesn't exist
        os.makedirs(self.path, exist_ok=True)

        # Create database marker file
        db_marker_path = os.path.join(self.path, f"{name}.valt")
        if not os.path.exists(db_marker_path):
            with open(db_marker_path, "w") as f:
                f.write("ValtDB Database Marker")

        # Load existing tables
        self._load_tables()

    def _decode_and_parse_json(self, data: Union[str, bytes, Any]) -> Dict[str, Any]:
        """Helper function to decode and parse JSON data."""
        if isinstance(data, bytes):
            return cast(Dict[str, Any], json.loads(data.decode('utf-8')))
        elif isinstance(data, str):
            return cast(Dict[str, Any], json.loads(data))
        else:
            return cast(Dict[str, Any], json.loads(str(data)))

    def _load_tables(self) -> None:
        """Load existing tables from database directory."""
        for table_name in self.list_tables():
            table_path = os.path.join(self.path, f"{table_name}.table")

            try:
                with open(table_path, "rb") as f:
                    raw_data = f.read()

                    if self._encryption_manager:
                        decrypted_data = self._encryption_manager.decrypt(raw_data)
                        table_data = self._decode_and_parse_json(decrypted_data)
                    else:
                        table_data = self._decode_and_parse_json(raw_data)

                    # Convert schema dict to Schema object
                    schema_dict = table_data.get("schema", {})
                    schema = Schema.from_dict(schema_dict)
                    
                    # Create table with schema
                    self._tables[table_name] = Table(
                        table_name, 
                        schema,
                        encryption_manager=self._encryption_manager
                    )
                
                    # Load data
                    for record in table_data.get("data", []):
                        self._tables[table_name].insert(record)

            except (IOError, json.JSONDecodeError) as e:
                raise ValtDBError(f"Failed to load table {table_name}: {str(e)}")

    def _save_table(self, name: str) -> None:
        """Save table to disk."""
        if name not in self._tables:
            raise ValtDBError(f"Table {name} does not exist")

        table = self._tables[name]
        table_path = os.path.join(self.path, f"{name}.table")

        # Convert table data to dict
        table_data = {
            "name": table.name,
            "schema": table.schema.to_dict(),
            "data": table._data
        }

        try:
            json_str = json.dumps(table_data)
            if self._encryption_manager:
                encrypted_data = self._encryption_manager.encrypt(json_str)
                with open(table_path, "wb") as f:
                    f.write(encrypted_data)
            else:
                with open(table_path, "w") as f:
                    json.dump(table_data, f, indent=2)
        except Exception as e:
            raise ValtDBError(f"Error saving table {name}: {str(e)}")

    def validate_data(self, table_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate data against table schema."""
        table = self.get_table(table_name)
        schema = table.schema
        
        if not isinstance(schema, Schema):
            raise ValtDBError("Invalid schema format")
        
        validated_data: Dict[str, Any] = {}
        
        for field_name, field_value in data.items():
            field = schema.get_field(field_name)
            if field is None:
                raise ValtDBError(f"Field {field_name} not in schema")
            
            try:
                validated_data[field_name] = self._convert_value(field_value, field.field_type)
            except (ValueError, TypeError) as e:
                raise ValtDBError(f"Invalid value for field {field_name}: {str(e)}")
        
        # Check for required fields
        for field_name, field in schema.fields.items():
            if field.required and field_name not in validated_data:
                raise ValtDBError(f"Required field {field_name} missing")
        
        return validated_data

    def _convert_value(self, value: Any, field_type: Optional[DataType]) -> Any:
        """Convert value to appropriate type."""
        if value is None:
            return None

        if field_type is None:
            return value

        try:
            if field_type == DataType.STRING:
                return str(value)
            elif field_type == DataType.INTEGER:
                return int(value)
            elif field_type == DataType.BOOLEAN:
                return bool(value)
            else:
                raise ValtDBError(f"Unsupported data type: {field_type}")
        except ValueError as e:
            raise ValtDBError(f"Cannot convert value: {value} to {field_type}: {str(e)}")

    def table(self, name: str, schema_dict: Optional[Dict[str, str]] = None) -> Table:
        """Create or get a table."""
        if name in self._tables:
            return self._tables[name]
        elif schema_dict is not None:
            return self.create_table(name, schema_dict)
        else:
            raise ValtDBError(f"Table {name} does not exist")

    def create_table(
            self, name: str, schema: Union[Dict[str, Any], Schema]
        ) -> 'Table':
        """Create a new table.

        Args:
            name: Name of the table
            schema: Table schema definition

        Returns:
            Table: The created table
        """
        if name in self._tables:
            raise ValtDBError(f"Table {name} already exists")

        # Convert schema dict to Schema object if needed
        if isinstance(schema, dict):
            table_schema = Schema.from_dict(schema)
        else:
            table_schema = schema

        # Create table with schema
        table = Table(
            name,
            table_schema,
            encryption_manager=self._encryption_manager
        )
        self._tables[name] = table
        self._save_table(name)
        return table

    def save(self):
        """Save all tables to disk."""
        for name, table in self._tables.items():
            self._save_table(name)

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
        table_path = os.path.join(self.path, f"{name}.table")
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
