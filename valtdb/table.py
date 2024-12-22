from datetime import datetime
from typing import Any, Dict, List, Optional, Union, cast

from .crypto.encryption import EncryptionManager
from .query import Query
from .schema import DataType, Schema, SchemaField

class Table:
    """Table class for storing and managing data."""

    def __init__(self, name: str, schema: Schema, encryption_manager: Optional[EncryptionManager] = None):
        """Initialize table with name and schema."""
        self.name = name
        self.schema = schema
        self._encryption = encryption_manager
        self._data: List[Dict[str, Any]] = []

    def _check_type_compatibility(self, value: Any, field_type: DataType) -> bool:
        """Check if value is compatible with field type."""
        if value is None:
            return True

        type_map = {
            DataType.STR: str,
            DataType.INT: int,
            DataType.FLOAT: float,
            DataType.BOOL: bool,
            DataType.DATETIME: datetime,
            DataType.BYTES: bytes,
            DataType.LIST: list,
            DataType.DICT: dict
        }

        expected_type = type_map.get(field_type)
        if not expected_type:
            return False

        return isinstance(value, expected_type)

    def _convert_value(self, value: Any, field_type: DataType) -> Any:
        """Convert value to appropriate type."""
        if value is None:
            return None

        try:
            if field_type == DataType.STR:
                return str(value)
            elif field_type == DataType.INT:
                return int(value)
            elif field_type == DataType.FLOAT:
                return float(value)
            elif field_type == DataType.BOOL:
                return bool(value)
            elif field_type == DataType.DATETIME:
                if isinstance(value, datetime):
                    return value
                elif isinstance(value, str):
                    return datetime.fromisoformat(value)
                else:
                    raise ValueError(f"Cannot convert {value} to datetime")
            elif field_type == DataType.BYTES:
                if isinstance(value, bytes):
                    return value
                elif isinstance(value, str):
                    return value.encode()
                else:
                    raise ValueError(f"Cannot convert {value} to bytes")
            elif field_type == DataType.LIST:
                if isinstance(value, list):
                    return value
                else:
                    raise ValueError(f"Cannot convert {value} to list")
            elif field_type == DataType.DICT:
                if isinstance(value, dict):
                    return value
                else:
                    raise ValueError(f"Cannot convert {value} to dict")
            else:
                raise ValueError(f"Unknown field type: {field_type}")
        except (ValueError, TypeError) as e:
            raise ValueError(f"Type conversion failed: {str(e)}")

    def _validate_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate data against schema."""
        validated_data: Dict[str, Any] = {}
        
        for field_name, field_def in self.schema.fields.items():
            if field_def.required and field_name not in data:
                raise ValueError(f"Required field '{field_name}' is missing")

            # Validate and convert each field
            value = data.get(field_name)
            if value is None and not field_def.required:
                validated_data[field_name] = None
                continue

            if field_def.field_type is None:
                raise ValueError(f"Field type not specified for field '{field_name}'")

            # Ensure field type is not None
            field_type = field_def.field_type

            # Check type compatibility and convert
            if not self._check_type_compatibility(value, field_type):
                converted_value = self._convert_value(value, field_type)
            else:
                converted_value = value

            # Encrypt if needed
            if hasattr(field_def, 'encrypted') and field_def.encrypted and self._encryption:
                if isinstance(converted_value, bytes):
                    converted_value = converted_value.decode('utf-8')
                converted_value = self._encryption.encrypt(converted_value)

            validated_data[field_name] = converted_value

        return validated_data

    def insert(self, data: Dict[str, Any]) -> None:
        """Insert data into table."""
        validated_data = self._validate_data(data)
        self._data.append(validated_data)

    def update(self, query: Query, updates: Dict[str, Any]) -> None:
        """Update records matching query."""
        validated_updates = self._validate_data(updates)
        for record in self._data:
            if query.matches(record):
                record.update(validated_updates)

    def delete(self, query: Query) -> None:
        """Delete records matching query."""
        self._data = [record for record in self._data if not query.matches(record)]

    def select(self, query: Optional[Query] = None) -> List[Dict[str, Any]]:
        """Select records matching query."""
        if query is None:
            return self._data.copy()
        return [record for record in self._data if query.matches(record)]

    def count(self, query: Optional[Query] = None) -> int:
        """Count records matching query."""
        return len(self.select(query))
