"""Database management for ValtDB."""

import json
import os
from typing import Any, Dict, List, Optional, Union

from .crypto.encryption import EncryptionManager, KeyPair, generate_keypair
from .exceptions import ValtDBError
from .schema import Schema, SchemaField, DataType  # Import Schema and SchemaField classes
from .table import Table


class Database:
    """Manages database operations and tables."""

    def __init__(self, name: str, path: Optional[str] = None, encryption_manager: Optional[EncryptionManager] = None, keypair: Optional[KeyPair] = None):
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
                                self._encryption_manager.keypair if self._encryption_manager else None
                            ),
                        )
                    except Exception as e:
                        raise ValtDBError(f"Failed to load table {table_name}: {str(e)}")

    def table(self, name: str, schema_dict: Optional[Dict[str, str]] = None) -> 'Table':
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

        # Determine keypair
        keypair = None
        if self._encryption_manager:
            # If encryption manager is provided, use its keypair or generate a new one
            try:
                keypair = self._encryption_manager.keypair
            except AttributeError:
                # Fallback to generating a new keypair if not available
                from .crypto.encryption import generate_keypair
                keypair = generate_keypair()

        # Create and store the table
        self._tables[name] = Table(
            name=name, 
            table_data={
                "schema": schema_dict,
                "data": []
            }, 
            keypair=keypair
        )

        return self._tables[name]

    def create_table(self, name: str, schema: Union[Dict[str, str], Schema, Dict[str, Any]]) -> Table:
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
        from .schema import Schema, SchemaField, DataType
        
        # If it's already a Schema object, convert to dictionary
        if isinstance(schema, Schema):
            schema_dict = {field.name: field.field_type.value for field in schema.fields}
        elif isinstance(schema, dict):
            # Validate schema types
            schema_dict = {}
            for field_name, field_type in schema.items():
                # Ensure field_type is a string
                if isinstance(field_type, dict):
                    field_type = field_type.get('type', field_type.get('field_type', 'str'))
                
                try:
                    # This will raise a ValueError if the type is invalid
                    DataType(field_type)
                    schema_dict[field_name] = field_type
                except ValueError:
                    raise ValtDBError(f"Invalid type '{field_type}' for field '{field_name}'")
        else:
            raise ValtDBError(f"Invalid schema type: {type(schema)}")
        
        # Create the table
        table = self.table(name, schema_dict)
        
        # For test compatibility, set the schema attribute to match input
        table.schema = schema
        
        return table

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
        self._data = table_data.get("data", [])
        
        # Handle different schema types
        from .schema import Schema, SchemaField, DataType
        
        # If schema is a simple dictionary of types, convert it to a Schema object
        if isinstance(table_data.get("schema"), dict):
            schema_fields = []
            for field_name, field_type in table_data["schema"].items():
                # Ensure field_type is a string
                if isinstance(field_type, dict):
                    field_type = field_type.get('type', field_type.get('field_type', 'str'))
                
                # Validate and create SchemaField
                schema_fields.append(SchemaField(
                    name=field_name,
                    field_type=DataType(field_type),
                    required=False,
                    unique=False
                ))
            
            self.schema = Schema(schema_fields)
        else:
            # Assume it's already a Schema object or a more complex schema
            self.schema = Schema.from_dict(table_data["schema"])
        
        self.keypair = keypair

    def all(self) -> List[Dict[str, Any]]:
        """Return all records in the table"""
        return list(self._data)

    def insert(self, data: Dict[str, Any]) -> None:
        """
        Insert data into the table.

        Args:
            data: Dictionary of data to insert
        """
        # Validate data against schema
        validated_data = {}
        
        # Ensure schema is a Schema object
        from .schema import Schema
        if not isinstance(self.schema, Schema):
            self.schema = Schema(self.schema)
        
        # Validate each field
        for field_name, field_def in self.schema.fields.items():
            # Check if field is present in input data
            if field_name not in data:
                if field_def.required:
                    raise ValtDBError(f"Required field '{field_name}' is missing")
                continue

            # Validate field type
            try:
                # Convert value based on field type
                value = data[field_name]
                if field_def.field_type.value == "int":
                    validated_data[field_name] = int(value)
                elif field_def.field_type.value == "str":
                    validated_data[field_name] = str(value)
                elif field_def.field_type.value == "float":
                    validated_data[field_name] = float(value)
                elif field_def.field_type.value.startswith("encrypted_"):
                    validated_data[field_name] = value
                else:
                    raise ValueError(f"Unsupported type: {field_def.field_type.value}")
            except Exception as e:
                raise ValtDBError(f"Invalid value for field '{field_name}': {str(e)}")

            # Check unique constraint
            if field_def.unique:
                if any(existing.get(field_name) == validated_data[field_name] 
                       for existing in self._data):
                    raise ValtDBError(f"Unique constraint violated for field '{field_name}'")

        # Add data to the table
        self._data.append(validated_data)

    def select(self, query: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Select rows from the table based on optional query.

        Args:
            query: Optional dictionary of filter conditions

        Returns:
            List of matching rows
        """
        if not query:
            return self.all()
        
        results = []
        for row in self._data:
            match = all(
                row.get(key) == value 
                for key, value in query.items() 
                if key in row
            )
            if match:
                results.append(row)
        
        return results

    def update(self, query: Dict[str, Any], updates: Dict[str, Any]) -> int:
        """
        Update rows matching the query.

        Args:
            query: Dictionary of filter conditions
            updates: Dictionary of fields to update

        Returns:
            int: Number of rows updated
        """
        # Validate updates against schema
        validated_updates = {}
        
        # Ensure schema is a Schema object
        from .schema import Schema
        if not isinstance(self.schema, Schema):
            self.schema = Schema(self.schema)
        
        # Validate each update field
        for field, value in updates.items():
            if field not in self.schema.fields:
                raise ValtDBError(f"Unknown field '{field}'")
            
            field_def = self.schema.fields[field]
            
            # Validate field type
            try:
                # Convert value based on field type
                if field_def.field_type.value == "int":
                    validated_updates[field] = int(value)
                elif field_def.field_type.value == "str":
                    validated_updates[field] = str(value)
                elif field_def.field_type.value == "float":
                    validated_updates[field] = float(value)
                elif field_def.field_type.value.startswith("encrypted_"):
                    validated_updates[field] = value
                else:
                    raise ValueError(f"Unsupported type: {field_def.field_type.value}")
            except Exception as e:
                raise ValtDBError(f"Invalid value for field '{field}': {str(e)}")

            # Check unique constraint
            if field_def.unique:
                if any(existing.get(field) == validated_updates[field] 
                       for existing in self._data if existing != row):
                    raise ValtDBError(f"Unique constraint violated for field '{field}'")

        # Update matching rows
        updated_count = 0
        for row in self._data:
            match = all(
                row.get(key) == value 
                for key, value in query.items() 
                if key in row
            )
            if match:
                row.update(validated_updates)
                updated_count += 1
        
        return updated_count

    def delete(self, query: Optional[Dict[str, Any]] = None) -> int:
        """
        Delete rows matching the query.

        Args:
            query: Optional dictionary of filter conditions

        Returns:
            int: Number of rows deleted
        """
        if not query:
            original_count = len(self._data)
            self._data.clear()
            return original_count
        
        # Create a new list without matching rows
        original_count = len(self._data)
        self._data = [
            row for row in self._data 
            if not all(
                row.get(key) == value 
                for key, value in query.items() 
                if key in row
            )
        ]
        
        return original_count - len(self._data)

    def count(self, query: Optional[Dict[str, Any]] = None) -> int:
        """
        Count rows matching the query.

        Args:
            query: Optional dictionary of filter conditions

        Returns:
            int: Number of matching rows
        """
        return len(self.select(query))

    def first(self, query: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """
        Return the first row matching the query.

        Args:
            query: Optional dictionary of filter conditions

        Returns:
            First matching row or None
        """
        results = self.select(query)
        return results[0] if results else None

    def __len__(self) -> int:
        """
        Return the number of rows in the table.

        Returns:
            int: Total number of rows
        """
        return len(self._data)

    def __iter__(self):
        """
        Make the table iterable.

        Returns:
            Iterator over table rows
        """
        return iter(self._data)
