import hashlib
import json
from typing import Any, Union


def hash_data(data: Any) -> str:
    """
    Create SHA256 hash of data.
    Data is first converted to JSON string to ensure consistent hashing.
    """
    if isinstance(data, (bytes, bytearray)):
        data_bytes = data
    else:
        data_bytes = json.dumps(data, sort_keys=True).encode()

    return hashlib.sha256(data_bytes).hexdigest()


def verify_hash(data: Any, hash_value: str) -> bool:
    """Verify if data matches the provided hash."""
    return hash_data(data) == hash_value
