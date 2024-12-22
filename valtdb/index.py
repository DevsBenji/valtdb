"""
Index management for ValtDB
"""
from typing import Any, Dict, List, Optional, Set
from collections import defaultdict
import bisect

class Index:
    def __init__(self, name: str, field: str, unique: bool = False):
        self.name = name
        self.field = field
        self.unique = unique
        self._index: Dict[Any, List[int]] = defaultdict(list)

    def add(self, value: Any, row_id: int):
        """Add value to index"""
        if self.unique and value in self._index:
            raise ValueError(f"Duplicate value for unique index {self.name}: {value}")
        
        bisect.insort(self._index[value], row_id)

    def remove(self, value: Any, row_id: int):
        """Remove value from index"""
        if value in self._index:
            try:
                idx = self._index[value].index(row_id)
                self._index[value].pop(idx)
                if not self._index[value]:
                    del self._index[value]
            except ValueError:
                pass

    def update(self, old_value: Any, new_value: Any, row_id: int):
        """Update value in index"""
        self.remove(old_value, row_id)
        self.add(new_value, row_id)

    def find(self, value: Any) -> List[int]:
        """Find row IDs for value"""
        return self._index.get(value, [])

    def find_range(self, start: Any, end: Any) -> List[int]:
        """Find row IDs for value range"""
        result = []
        for value in self._index:
            if start <= value <= end:
                result.extend(self._index[value])
        return sorted(result)

    def clear(self):
        """Clear index"""
        self._index.clear()

class CompoundIndex(Index):
    def __init__(self, name: str, fields: List[str], unique: bool = False):
        super().__init__(name, ",".join(fields), unique)
        self.fields = fields

    def _make_key(self, values: List[Any]) -> tuple:
        """Create compound key from values"""
        return tuple(values)

    def add(self, values: List[Any], row_id: int):
        """Add compound value to index"""
        key = self._make_key(values)
        super().add(key, row_id)

    def remove(self, values: List[Any], row_id: int):
        """Remove compound value from index"""
        key = self._make_key(values)
        super().remove(key, row_id)

    def update(self, old_values: List[Any], new_values: List[Any], row_id: int):
        """Update compound value in index"""
        old_key = self._make_key(old_values)
        new_key = self._make_key(new_values)
        super().update(old_key, new_key, row_id)

    def find(self, values: List[Any]) -> List[int]:
        """Find row IDs for compound value"""
        key = self._make_key(values)
        return super().find(key)

class IndexManager:
    def __init__(self):
        self.indexes: Dict[str, Index] = {}

    def create_index(self, name: str, field: str, unique: bool = False) -> Index:
        """Create new index"""
        if name in self.indexes:
            raise ValueError(f"Index {name} already exists")
            
        index = Index(name, field, unique)
        self.indexes[name] = index
        return index

    def create_compound_index(self, name: str, fields: List[str], unique: bool = False) -> CompoundIndex:
        """Create new compound index"""
        if name in self.indexes:
            raise ValueError(f"Index {name} already exists")
            
        index = CompoundIndex(name, fields, unique)
        self.indexes[name] = index
        return index

    def drop_index(self, name: str):
        """Drop index"""
        if name in self.indexes:
            del self.indexes[name]

    def get_index(self, name: str) -> Optional[Index]:
        """Get index by name"""
        return self.indexes.get(name)

    def rebuild_indexes(self, data: List[Dict[str, Any]]):
        """Rebuild all indexes"""
        for index in self.indexes.values():
            index.clear()
            
            if isinstance(index, CompoundIndex):
                for i, row in enumerate(data):
                    values = [row.get(field) for field in index.fields]
                    if all(v is not None for v in values):
                        index.add(values, i)
            else:
                for i, row in enumerate(data):
                    value = row.get(index.field)
                    if value is not None:
                        index.add(value, i)

    def update_indexes(self, old_row: Dict[str, Any], new_row: Dict[str, Any], row_id: int):
        """Update all indexes for row update"""
        for index in self.indexes.values():
            if isinstance(index, CompoundIndex):
                old_values = [old_row.get(field) for field in index.fields]
                new_values = [new_row.get(field) for field in index.fields]
                if all(v is not None for v in old_values + new_values):
                    index.update(old_values, new_values, row_id)
            else:
                old_value = old_row.get(index.field)
                new_value = new_row.get(index.field)
                if old_value is not None and new_value is not None:
                    index.update(old_value, new_value, row_id)
