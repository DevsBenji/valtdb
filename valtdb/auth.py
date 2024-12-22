"""
Authentication and authorization for ValtDB
"""
from typing import Optional, Dict, Any, List
import jwt
import bcrypt
import secrets
from datetime import datetime, timedelta
from .exceptions import ValtDBError

class User:
    def __init__(
        self,
        username: str,
        password_hash: str,
        roles: List[str] = None,
        is_active: bool = True
    ):
        self.username = username
        self.password_hash = password_hash
        self.roles = roles or ["user"]
        self.is_active = is_active

    @classmethod
    def create(cls, username: str, password: str, roles: List[str] = None) -> 'User':
        """Create new user with hashed password"""
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        return cls(username, password_hash.decode(), roles)

    def verify_password(self, password: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode(), self.password_hash.encode())

    def to_dict(self) -> Dict[str, Any]:
        """Convert user to dictionary"""
        return {
            "username": self.username,
            "password_hash": self.password_hash,
            "roles": self.roles,
            "is_active": self.is_active
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'User':
        """Create user from dictionary"""
        return cls(**data)

class AuthManager:
    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = secret_key or secrets.token_hex(32)
        self.users: Dict[str, User] = {}
        self.token_blacklist: set = set()

    def add_user(self, username: str, password: str, roles: List[str] = None) -> User:
        """Add new user"""
        if username in self.users:
            raise ValtDBError(f"User {username} already exists")
        
        user = User.create(username, password, roles)
        self.users[username] = user
        return user

    def remove_user(self, username: str):
        """Remove user"""
        if username not in self.users:
            raise ValtDBError(f"User {username} not found")
        del self.users[username]

    def authenticate(self, username: str, password: str) -> Optional[str]:
        """Authenticate user and return JWT token"""
        user = self.users.get(username)
        if not user or not user.is_active:
            return None

        if not user.verify_password(password):
            return None

        # Generate JWT token
        payload = {
            "sub": username,
            "roles": user.roles,
            "exp": datetime.utcnow() + timedelta(hours=24)
        }
        return jwt.encode(payload, self.secret_key, algorithm="HS256")

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token and return payload"""
        if token in self.token_blacklist:
            return None

        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            username = payload.get("sub")
            if username not in self.users or not self.users[username].is_active:
                return None
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def invalidate_token(self, token: str):
        """Add token to blacklist"""
        self.token_blacklist.add(token)

    def has_role(self, token: str, required_role: str) -> bool:
        """Check if user has required role"""
        payload = self.verify_token(token)
        if not payload:
            return False
        return required_role in payload.get("roles", [])

class Permission:
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description

class Role:
    def __init__(self, name: str, permissions: List[Permission] = None):
        self.name = name
        self.permissions = permissions or []

    def has_permission(self, permission: str) -> bool:
        """Check if role has permission"""
        return any(p.name == permission for p in self.permissions)

class RBAC:
    def __init__(self):
        self.roles: Dict[str, Role] = {}
        self.permissions: Dict[str, Permission] = {}

    def add_permission(self, name: str, description: str = "") -> Permission:
        """Add new permission"""
        if name in self.permissions:
            raise ValtDBError(f"Permission {name} already exists")
        permission = Permission(name, description)
        self.permissions[name] = permission
        return permission

    def add_role(self, name: str, permissions: List[str] = None) -> Role:
        """Add new role"""
        if name in self.roles:
            raise ValtDBError(f"Role {name} already exists")
        
        role_permissions = []
        if permissions:
            for perm_name in permissions:
                if perm_name not in self.permissions:
                    raise ValtDBError(f"Permission {perm_name} not found")
                role_permissions.append(self.permissions[perm_name])
        
        role = Role(name, role_permissions)
        self.roles[name] = role
        return role

    def remove_role(self, name: str):
        """Remove role"""
        if name not in self.roles:
            raise ValtDBError(f"Role {name} not found")
        del self.roles[name]

    def grant_permission(self, role_name: str, permission_name: str):
        """Grant permission to role"""
        if role_name not in self.roles:
            raise ValtDBError(f"Role {role_name} not found")
        if permission_name not in self.permissions:
            raise ValtDBError(f"Permission {permission_name} not found")
            
        role = self.roles[role_name]
        permission = self.permissions[permission_name]
        if permission not in role.permissions:
            role.permissions.append(permission)

    def revoke_permission(self, role_name: str, permission_name: str):
        """Revoke permission from role"""
        if role_name not in self.roles:
            raise ValtDBError(f"Role {role_name} not found")
            
        role = self.roles[role_name]
        role.permissions = [p for p in role.permissions if p.name != permission_name]
