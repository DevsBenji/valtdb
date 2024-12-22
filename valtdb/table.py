from typing import Any, Dict, List, Optional, Union

from .crypto import decrypt_data, encrypt_data, hash_data, verify_hash
from .exceptions import ValtDBError
from .index import IndexManager
from .query import Query, QueryExecutor
from .schema import DataType, Schema, SchemaField


class Table:
    def __init__(self, name: str, table_data: Dict[str, Any], keypair=None):
        """Initialize table.

        Args:
            name: Name of the table
            table_data: Dictionary containing table data and schema
            keypair: Optional keypair for encryption
        """
        self.name = name
        self.schema = Schema(table_data["schema"])
        self.keypair = keypair
        self._data: List[Dict[str, Any]] = table_data.get("data", [])
        self.index_manager = IndexManager()
        self._setup_indexes()

    def _setup_indexes(self):
        """Setup initial indexes"""
        # Create indexes for unique fields
        for field_name, field in self.schema.fields.items():
            if field.unique:
                self.index_manager.create_index(f"{field_name}_unique", field_name, unique=True)

    def insert(self, row: Dict[str, Any]) -> int:
        """Insert new row"""
        # Validate data against schema
        validated_data = self.schema.validate_data(row)

        # Encrypt sensitive fields
        if self.keypair:
            for field_name, value in validated_data.items():
                field = self.schema.fields[field_name]
                if field.field_type.value.startswith("encrypted_"):
                    validated_data[field_name] = encrypt_data(value, self.keypair.public_key)

        # Add hash for integrity
        validated_data["_hash"] = hash_data(validated_data)

        # Insert data
        row_id = len(self._data)
        self._data.append(validated_data)

        # Update indexes
        self.index_manager.update_indexes({}, validated_data, row_id)

        return row_id

    def select(self, query: Optional[Query] = None) -> List[Dict[str, Any]]:
        """Select rows using query"""
        # Execute query
        if query:
            results = QueryExecutor.execute_query(self._data, query)
        else:
            results = self._data.copy()

        # Decrypt sensitive fields
        if self.keypair:
            for row in results:
                for field_name, value in row.items():
                    if field_name == "_hash":
                        continue
                    field = self.schema.fields.get(field_name)
                    if field and field.field_type.value.startswith("encrypted_"):
                        row[field_name] = decrypt_data(value, self.keypair.private_key)

                # Verify integrity
                row_data = {k: v for k, v in row.items() if k != "_hash"}
                if not verify_hash(row_data, row["_hash"]):
                    raise ValtDBError(f"Data integrity check failed for row in table {self.name}")

        return results

    def update(self, query: Query, new_values: Dict[str, Any]) -> int:
        """Update rows matching query"""
        # Find matching rows
        rows_to_update = self.select(query)

        # Validate new values
        validated_updates = {}
        for field_name, value in new_values.items():
            if field_name not in self.schema.fields:
                raise ValtDBError(f"Unknown field '{field_name}'")
            field = self.schema.fields[field_name]
            validated_updates[field_name] = self._validate_field(field, value)

        # Update rows
        updated_count = 0
        for row in rows_to_update:
            row_id = self._data.index(row)
            old_row = row.copy()

            # Update values
            row.update(validated_updates)

            # Re-encrypt if needed
            if self.keypair:
                for field_name, value in row.items():
                    if field_name == "_hash":
                        continue
                    field = self.schema.fields.get(field_name)
                    if field and field.field_type.value.startswith("encrypted_"):
                        row[field_name] = encrypt_data(value, self.keypair.public_key)

            # Update hash
            row["_hash"] = hash_data(row)

            # Update indexes
            self.index_manager.update_indexes(old_row, row, row_id)
            updated_count += 1

        return updated_count

    def delete(self, query: Query) -> int:
        """Delete rows matching query"""
        rows_to_delete = self.select(query)
        deleted_count = 0

        for row in reversed(rows_to_delete):  # Reverse to handle indexes correctly
            row_id = self._data.index(row)

            # Remove from indexes
            self.index_manager.update_indexes(row, {}, row_id)

            # Remove row
            self._data.pop(row_id)
            deleted_count += 1

        return deleted_count

    def create_index(self, name: str, field: str, unique: bool = False):
        """Create new index"""
        index = self.index_manager.create_index(name, field, unique)
        # Build index
        for i, row in enumerate(self._data):
            value = row.get(field)
            if value is not None:
                index.add(value, i)

    def create_compound_index(self, name: str, fields: List[str], unique: bool = False):
        """Create new compound index"""
        index = self.index_manager.create_compound_index(name, fields, unique)
        # Build index
        for i, row in enumerate(self._data):
            values = [row.get(field) for field in fields]
            if all(v is not None for v in values):
                index.add(values, i)

    def drop_index(self, name: str):
        """Drop index"""
        self.index_manager.drop_index(name)

    def count(self, query: Optional[Query] = None) -> int:
        """Count rows matching query"""
        return len(self.select(query))

    def aggregate(
        self,
        query: Optional[Query] = None,
        group_by: Optional[List[str]] = None,
        aggregations: Dict[str, List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Perform aggregation operations"""
        results = self.select(query)

        if not group_by:
            return self._aggregate_all(results, aggregations)

        # Group results
        groups = {}
        for row in results:
            key = tuple(row[field] for field in group_by)
            if key not in groups:
                groups[key] = []
            groups[key].append(row)

        # Aggregate each group
        aggregated = []
        for key, group in groups.items():
            result = {field: value for field, value in zip(group_by, key)}
            agg_values = self._aggregate_all(group, aggregations)
            result.update(agg_values[0] if agg_values else {})
            aggregated.append(result)

        return aggregated

    def _aggregate_all(
        self, rows: List[Dict[str, Any]], aggregations: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        """Perform aggregation on all rows"""
        result = {}

        for field, operations in aggregations.items():
            values = [row[field] for row in rows if field in row]

            for op in operations:
                if op == "count":
                    result[f"{field}_count"] = len(values)
                elif op == "sum":
                    result[f"{field}_sum"] = sum(values)
                elif op == "avg":
                    result[f"{field}_avg"] = sum(values) / len(values) if values else 0
                elif op == "min":
                    result[f"{field}_min"] = min(values) if values else None
                elif op == "max":
                    result[f"{field}_max"] = max(values) if values else None

        return [result]

    def to_dict(self) -> Dict:
        """Convert table to dictionary for storage"""
        return {"schema": self.schema.to_dict(), "data": self._data}

    def _validate_field(self, field: SchemaField, value: Any) -> Any:
        """Validate field value"""
        if field.field_type.value == DataType.STRING:
            if not isinstance(value, str):
                raise ValtDBError(f"Invalid type for field '{field.name}': expected string")
        elif field.field_type.value == DataType.INTEGER:
            if not isinstance(value, int):
                raise ValtDBError(f"Invalid type for field '{field.name}': expected integer")
        elif field.field_type.value == DataType.FLOAT:
            if not isinstance(value, (int, float)):
                raise ValtDBError(f"Invalid type for field '{field.name}': expected float")
        elif field.field_type.value == DataType.BOOLEAN:
            if not isinstance(value, bool):
                raise ValtDBError(f"Invalid type for field '{field.name}': expected boolean")
        elif field.field_type.value == DataType.ENCRYPTED_STRING:
            if not isinstance(value, str):
                raise ValtDBError(f"Invalid type for field '{field.name}': expected string")
        elif field.field_type.value == DataType.ENCRYPTED_INTEGER:
            if not isinstance(value, int):
                raise ValtDBError(f"Invalid type for field '{field.name}': expected integer")
        elif field.field_type.value == DataType.ENCRYPTED_FLOAT:
            if not isinstance(value, (int, float)):
                raise ValtDBError(f"Invalid type for field '{field.name}': expected float")
        elif field.field_type.value == DataType.ENCRYPTED_BOOLEAN:
            if not isinstance(value, bool):
                raise ValtDBError(f"Invalid type for field '{field.name}': expected boolean")

        return value
