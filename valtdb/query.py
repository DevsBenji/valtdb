"""
Query builder module for ValtDB
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Union, cast


class Operator(Enum):
    EQUALS = "="
    NOT_EQUALS = "!="
    GREATER_THAN = ">"
    LESS_THAN = "<"
    GREATER_EQUAL = ">="
    LESS_EQUAL = "<="
    CONTAINS = "CONTAINS"
    NOT_CONTAINS = "NOT_CONTAINS"
    IN = "IN"
    NOT_IN = "NOT_IN"


class Query:
    """Query builder for database operations."""
    def __init__(self):
        self.filters: List[Dict[str, Any]] = []
        self.or_filters: List[Dict[str, Any]] = []

    def filter(self, field: str, operator: Operator, value: Any) -> 'Query':
        """Add a filter condition."""
        self.filters.append({
            "field": field,
            "operator": operator,
            "value": value
        })
        return self

    def or_filter(self, field: str, operator: Operator, value: Any) -> 'Query':
        """Add an OR filter condition."""
        self.or_filters.append({
            "field": field,
            "operator": operator,
            "value": value
        })
        return self

    def matches(self, record: Dict[str, Any]) -> bool:
        """Check if record matches query conditions."""
        # If no filters, match all records
        if not self.filters and not self.or_filters:
            return True

        # Check AND conditions
        matches_filters = True
        if self.filters:
            matches_filters = all(self._check_condition(record, f) for f in self.filters)

        # Check OR conditions
        matches_or_filters = False
        if self.or_filters:
            matches_or_filters = any(self._check_condition(record, f) for f in self.or_filters)

        # Return true if either all AND conditions match, or any OR condition matches
        return bool(matches_filters or matches_or_filters)

    def _check_condition(self, record: Dict[str, Any], condition: Dict[str, Any]) -> bool:
        """Check if record matches a single condition."""
        field = condition["field"]
        operator = condition["operator"]
        value = condition["value"]

        if field not in record:
            return False

        record_value = record[field]

        try:
            if operator == Operator.EQUALS:
                return bool(record_value == value)
            elif operator == Operator.NOT_EQUALS:
                return bool(record_value != value)
            elif operator == Operator.GREATER_THAN:
                return bool(record_value > value)
            elif operator == Operator.LESS_THAN:
                return bool(record_value < value)
            elif operator == Operator.GREATER_EQUAL:
                return bool(record_value >= value)
            elif operator == Operator.LESS_EQUAL:
                return bool(record_value <= value)
            elif operator == Operator.CONTAINS:
                return bool(value in str(record_value))
            elif operator == Operator.NOT_CONTAINS:
                return bool(value not in str(record_value))
            elif operator == Operator.IN:
                return bool(record_value in value)
            elif operator == Operator.NOT_IN:
                return bool(record_value not in value)
            else:
                raise ValueError(f"Unknown operator: {operator}")
        except (TypeError, ValueError):
            return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert query to dictionary."""
        return {
            "filters": self.filters,
            "or_filters": self.or_filters
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Query':
        """Create query from dictionary."""
        query = cls()
        query.filters = data.get("filters", [])
        query.or_filters = data.get("or_filters", [])
        return query


class QueryExecutor:
    @staticmethod
    def evaluate_condition(row: Dict[str, Any], condition: Dict[str, Any]) -> bool:
        """Evaluate single condition"""
        field = condition["field"]
        op = condition["op"]
        value = condition["value"]

        if field not in row:
            return False

        row_value = row[field]

        def safe_compare(a: Any, b: Any) -> bool:
            """Safely compare two values"""
            def _is_numeric(x: Any) -> bool:
                return isinstance(x, (int, float))

            def _is_comparable_list(x: Any) -> bool:
                return isinstance(x, (list, tuple, set))

            def _compare_numeric() -> bool:
                if not (_is_numeric(a) and _is_numeric(b)):
                    return False
                
                if op == Operator.GREATER_THAN:
                    return bool(a > b)
                elif op == Operator.LESS_THAN:
                    return bool(a < b)
                elif op == Operator.GREATER_EQUAL:
                    return bool(a >= b)
                elif op == Operator.LESS_EQUAL:
                    return bool(a <= b)
                return False

            def _compare_equality() -> bool:
                if op == Operator.EQUALS:
                    return bool(a == b)
                elif op == Operator.NOT_EQUALS:
                    return bool(a != b)
                return False

            def _compare_membership() -> bool:
                if op == Operator.IN:
                    return bool(_is_comparable_list(b) and a in b)
                return False

            def _compare_between() -> bool:
                if (op == Operator.GREATER_THAN and 
                    _is_comparable_list(b) and 
                    len(b) == 2 and 
                    all(_is_numeric(x) for x in b) and 
                    _is_numeric(a)):
                    return bool(b[0] <= a <= b[1])
                return False

            def _compare_like() -> bool:
                if op == Operator.CONTAINS:
                    return bool(QueryExecutor._match_pattern(str(a), str(b)))
                return False

            result = (
                _compare_numeric() or 
                _compare_equality() or 
                _compare_membership() or 
                _compare_between() or 
                _compare_like()
            )
            return bool(result)

        try:
            return safe_compare(row_value, value)
        except Exception:
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
                QueryExecutor.evaluate_condition(row, cond) for cond in query_dict["filters"]
            ):
                result.append(row)

        # Apply sorting
        for sort_rule in reversed(query_dict["sort_by"]):
            result.sort(
                key=lambda x: x.get(sort_rule["field"], None), 
                reverse=not sort_rule["ascending"]
            )

        # Apply offset and limit
        if query_dict["offset"]:
            result = result[query_dict["offset"] :]
        if query_dict["limit"]:
            result = result[: query_dict["limit"]]

        return result
