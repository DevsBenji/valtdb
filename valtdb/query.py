"""
Query builder module for ValtDB
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Union


class Operator(Enum):
    EQ = "eq"  # ==
    NE = "ne"  # !=
    GT = "gt"  # >
    LT = "lt"  # <
    GTE = "gte"  # >=
    LTE = "lte"  # <=
    IN = "in"  # in list
    LIKE = "like"  # pattern matching
    BETWEEN = "between"  # between range


class Query:
    def __init__(self):
        self._conditions = []
        self._sort_by = []
        self._limit = None
        self._offset = None

    def filter(self, field: str, operator: Operator, value: Any) -> "Query":
        """Add filter condition"""
        self._conditions.append({"field": field, "op": operator, "value": value})
        return self

    def sort(self, field: str, ascending: bool = True) -> "Query":
        """Add sort condition"""
        self._sort_by.append({"field": field, "ascending": ascending})
        return self

    def limit(self, limit: int) -> "Query":
        """Set limit"""
        self._limit = limit
        return self

    def offset(self, offset: int) -> "Query":
        """Set offset"""
        self._offset = offset
        return self

    def to_dict(self) -> Dict:
        """Convert query to dictionary"""
        return {
            "conditions": self._conditions,
            "sort_by": self._sort_by,
            "limit": self._limit,
            "offset": self._offset,
        }


class QueryExecutor:
    @staticmethod
    def evaluate_condition(row: Dict[str, Any], condition: Dict) -> bool:
        """Evaluate single condition"""
        field = condition["field"]
        op = condition["op"]
        value = condition["value"]

        if field not in row:
            return False

        row_value = row[field]

        if op == Operator.EQ:
            return row_value == value
        elif op == Operator.NE:
            return row_value != value
        elif op == Operator.GT:
            return row_value > value
        elif op == Operator.LT:
            return row_value < value
        elif op == Operator.GTE:
            return row_value >= value
        elif op == Operator.LTE:
            return row_value <= value
        elif op == Operator.IN:
            return row_value in value
        elif op == Operator.LIKE:
            return self._match_pattern(str(row_value), str(value))
        elif op == Operator.BETWEEN:
            return value[0] <= row_value <= value[1]

        return False

    @staticmethod
    def _match_pattern(text: str, pattern: str) -> bool:
        """Simple pattern matching with * wildcard"""
        if pattern == "*":
            return True

        parts = pattern.split("*")
        if len(parts) == 1:
            return text == pattern

        if not text.startswith(parts[0]):
            return False

        if not text.endswith(parts[-1]):
            return False

        pos = 0
        for part in parts[1:-1]:
            pos = text.find(part, pos)
            if pos == -1:
                return False
            pos += len(part)

        return True

    @staticmethod
    def execute_query(data: List[Dict[str, Any]], query: Query) -> List[Dict[str, Any]]:
        """Execute query on data"""
        query_dict = query.to_dict()

        # Apply conditions
        result = []
        for row in data:
            if all(
                QueryExecutor.evaluate_condition(row, cond) for cond in query_dict["conditions"]
            ):
                result.append(row)

        # Apply sorting
        for sort_rule in reversed(query_dict["sort_by"]):
            result.sort(key=lambda x: x.get(sort_rule["field"]), reverse=not sort_rule["ascending"])

        # Apply offset and limit
        if query_dict["offset"]:
            result = result[query_dict["offset"] :]
        if query_dict["limit"]:
            result = result[: query_dict["limit"]]

        return result
