"""
Schema validation and management for ValtDB
"""
from typing import Any, Dict, List, Optional, Union
from enum import Enum
from .exceptions import ValtDBError

class DataType(Enum):
    INT = "int"
    FLOAT = "float"
    STR = "str"
    BOOL = "bool"
    LIST = "list"
    DICT = "dict"
    ENCRYPTED_INT = "encrypted_int"
    ENCRYPTED_FLOAT = "encrypted_float"
    ENCRYPTED_STR = "encrypted_str"
    ENCRYPTED_DICT = "encrypted_dict"

class SchemaField:
    def __init__(
        self,
        name: str,
        field_type: DataType,
        required: bool = True,
        unique: bool = False,
        default: Any = None,
        min_value: Optional[Union[int, float]] = None,
        max_value: Optional[Union[int, float]] = None,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
        pattern: Optional[str] = None,
        choices: Optional[List[Any]] = None
    ):
        self.name = name
        self.field_type = field_type
        self.required = required
        self.unique = unique
        self.default = default
        self.min_value = min_value
        self.max_value = max_value
        self.min_length = min_length
        self.max_length = max_length
        self.pattern = pattern
        self.choices = choices

    def to_dict(self) -> Dict:
        """Convert field to dictionary"""
        return {
            "name": self.name,
            "type": self.field_type.value,
            "required": self.required,
            "unique": self.unique,
            "default": self.default,
            "min_value": self.min_value,
            "max_value": self.max_value,
            "min_length": self.min_length,
            "max_length": self.max_length,
            "pattern": self.pattern,
            "choices": self.choices
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'SchemaField':
        """Create field from dictionary"""
        return cls(
            name=data["name"],
            field_type=DataType(data["type"]),
            required=data.get("required", True),
            unique=data.get("unique", False),
            default=data.get("default"),
            min_value=data.get("min_value"),
            max_value=data.get("max_value"),
            min_length=data.get("min_length"),
            max_length=data.get("max_length"),
            pattern=data.get("pattern"),
            choices=data.get("choices")
        )

class Schema:
    def __init__(self, schema_data: Union[List[SchemaField], Dict[str, str]]):
        """Initialize schema.
        
        Args:
            schema_data: Either a list of SchemaField objects or a dictionary mapping field names to types
        """
        if isinstance(schema_data, dict):
            self.fields = {}
            for name, field_type in schema_data.items():
                try:
                    data_type = DataType(field_type)
                    self.fields[name] = SchemaField(name=name, field_type=data_type)
                except ValueError:
                    raise ValtDBError(f"Invalid field type '{field_type}' for field '{name}'")
        else:
            self.fields = {field.name: field for field in schema_data}
        self._validate_schema()

    def _validate_schema(self):
        """Validate schema configuration"""
        # Check for duplicate field names
        if len(self.fields) != len(set(f.name for f in self.fields.values())):
            raise ValtDBError("Duplicate field names in schema")

    def validate_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate data against schema"""
        validated = {}
        
        # Check required fields
        for name, field in self.fields.items():
            if field.required and name not in data:
                if field.default is not None:
                    validated[name] = field.default
                else:
                    raise ValtDBError(f"Required field '{name}' is missing")

        # Validate each field
        for name, value in data.items():
            if name not in self.fields:
                raise ValtDBError(f"Unknown field '{name}'")
                
            field = self.fields[name]
            validated[name] = self._validate_field(field, value)

        return validated

    def _validate_field(self, field: SchemaField, value: Any) -> Any:
        """Validate single field"""
        if value is None:
            if field.required:
                raise ValtDBError(f"Field '{field.name}' cannot be None")
            return None

        # Type validation
        if field.field_type in [DataType.INT, DataType.ENCRYPTED_INT]:
            if not isinstance(value, int):
                raise ValtDBError(f"Field '{field.name}' must be an integer")
        elif field.field_type in [DataType.FLOAT, DataType.ENCRYPTED_FLOAT]:
            if not isinstance(value, (int, float)):
                raise ValtDBError(f"Field '{field.name}' must be a number")
        elif field.field_type in [DataType.STR, DataType.ENCRYPTED_STR]:
            if not isinstance(value, str):
                raise ValtDBError(f"Field '{field.name}' must be a string")
        elif field.field_type == DataType.BOOL:
            if not isinstance(value, bool):
                raise ValtDBError(f"Field '{field.name}' must be a boolean")
        elif field.field_type == DataType.LIST:
            if not isinstance(value, list):
                raise ValtDBError(f"Field '{field.name}' must be a list")
        elif field.field_type in [DataType.DICT, DataType.ENCRYPTED_DICT]:
            if not isinstance(value, dict):
                raise ValtDBError(f"Field '{field.name}' must be a dictionary")

        # Value range validation
        if field.min_value is not None and value < field.min_value:
            raise ValtDBError(f"Field '{field.name}' value must be >= {field.min_value}")
        if field.max_value is not None and value > field.max_value:
            raise ValtDBError(f"Field '{field.name}' value must be <= {field.max_value}")

        # Length validation
        if isinstance(value, (str, list, dict)):
            if field.min_length is not None and len(value) < field.min_length:
                raise ValtDBError(f"Field '{field.name}' length must be >= {field.min_length}")
            if field.max_length is not None and len(value) > field.max_length:
                raise ValtDBError(f"Field '{field.name}' length must be <= {field.max_length}")

        # Pattern validation
        if field.pattern and isinstance(value, str):
            import re
            if not re.match(field.pattern, value):
                raise ValtDBError(f"Field '{field.name}' does not match pattern {field.pattern}")

        # Choices validation
        if field.choices is not None and value not in field.choices:
            raise ValtDBError(f"Field '{field.name}' value must be one of {field.choices}")

        return value

    def to_dict(self) -> Dict:
        """Convert schema to dictionary"""
        return {
            name: field.to_dict() for name, field in self.fields.items()
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'Schema':
        """Create schema from dictionary"""
        fields = [SchemaField.from_dict({**field_data, "name": name})
                 for name, field_data in data.items()]
        return cls(fields)
