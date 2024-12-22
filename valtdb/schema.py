"""
Schema validation and management for ValtDB
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Union

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
        field_type: Optional[DataType] = None,
        data_type: Optional[DataType] = None,
        required: bool = True,
        unique: bool = False,
        default: Any = None,
        min_value: Optional[Union[int, float]] = None,
        max_value: Optional[Union[int, float]] = None,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
        pattern: Optional[str] = None,
        choices: Optional[List[Any]] = None,
        encrypted: bool = False,
    ):
        # Prefer field_type, but fall back to data_type for backward compatibility
        self.name = name
        self.field_type = field_type or data_type
        if self.field_type is None:
            raise ValtDBError(f"Field type must be specified for field {name}")

        # If encrypted flag is set, modify field type to encrypted variant
        if encrypted:
            encrypted_type_name = f"ENCRYPTED_{self.field_type.name.lower()}"
            try:
                self.field_type = DataType[encrypted_type_name]
            except KeyError:
                # If specific encrypted type doesn't exist, use a generic encrypted type
                self.field_type = DataType.ENCRYPTED_STR

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
            "choices": self.choices,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "SchemaField":
        """Create field from dictionary"""
        return cls(
            name=data["name"],
            field_type=DataType(data.get("type", data.get("data_type"))),
            required=data.get("required", True),
            unique=data.get("unique", False),
            default=data.get("default"),
            min_value=data.get("min_value"),
            max_value=data.get("max_value"),
            min_length=data.get("min_length"),
            max_length=data.get("max_length"),
            pattern=data.get("pattern"),
            choices=data.get("choices"),
        )


class Schema:
    def __init__(self, schema_data: Union[List[SchemaField], Dict[str, str], Dict[str, Any]]):
        """Initialize schema.

        Args:
            schema_data: Either a list of SchemaField objects, 
                         a dictionary mapping field names to types, 
                         or a dictionary with more complex field definitions
        """
        # Handle different input types
        self.fields = {}
        
        if isinstance(schema_data, list):
            # List of SchemaField objects
            self.fields = {field.name: field for field in schema_data}
        elif isinstance(schema_data, dict):
            for name, field_def in schema_data.items():
                # Handle different input formats
                if isinstance(field_def, str):
                    # Simple type string
                    try:
                        data_type = DataType(field_def)
                        self.fields[name] = SchemaField(
                            name=name, 
                            field_type=data_type, 
                            required=False, 
                            unique=False
                        )
                    except ValueError:
                        raise ValtDBError(f"Invalid field type '{field_def}' for field '{name}'")
                elif isinstance(field_def, dict):
                    # More complex type definition
                    try:
                        # Extract type, defaulting to 'str' if not specified
                        type_str = field_def.get('type', field_def.get('field_type', 'str'))
                        data_type = DataType(type_str)
                        
                        # Create SchemaField with additional parameters
                        self.fields[name] = SchemaField(
                            name=name,
                            field_type=data_type,
                            required=field_def.get('required', False),
                            unique=field_def.get('unique', False),
                            default=field_def.get('default'),
                            min_value=field_def.get('min_value'),
                            max_value=field_def.get('max_value')
                        )
                    except ValueError:
                        raise ValtDBError(f"Invalid field type '{type_str}' for field '{name}'")
                else:
                    raise ValtDBError(f"Invalid schema definition for field '{name}'")
        else:
            raise ValtDBError(f"Invalid schema type: {type(schema_data)}")
        
        # Validate schema configuration
        self._validate_schema()

    def _validate_schema(self):
        """Validate schema configuration"""
        # Check for duplicate field names
        if len(self.fields) != len(set(f.name for f in self.fields.values())):
            raise ValtDBError("Duplicate field names in schema")

    def validate_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate input data against the schema.

        Args:
            data: Dictionary of data to validate

        Returns:
            Validated data dictionary
        """
        validated_data = {}
        for field_name, field_def in self.fields.items():
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

        return validated_data

    def to_dict(self) -> Dict:
        """Convert schema to dictionary"""
        return {name: field.to_dict() for name, field in self.fields.items()}

    @classmethod
    def from_dict(cls, data: Dict) -> "Schema":
        """Create schema from dictionary"""
        fields = [
            SchemaField.from_dict({**field_data, "name": name}) for name, field_data in data.items()
        ]
        return cls(fields)
