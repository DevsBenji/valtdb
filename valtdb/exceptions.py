"""ValtDB exceptions module."""

class ValtDBError(Exception):
    """Base exception for ValtDB errors."""
    pass

class ValidationError(ValtDBError):
    """Exception raised for validation errors."""
    pass

class SchemaError(ValtDBError):
    """Exception raised for schema errors."""
    pass

class QueryError(ValtDBError):
    """Exception raised for query errors."""
    pass

class AuthenticationError(ValtDBError):
    """Exception raised for authentication errors."""
    pass

class EncryptionError(ValtDBError):
    """Exception raised for encryption errors."""
    pass

class SSHError(ValtDBError):
    """Exception raised for SSH-related errors."""
    pass
