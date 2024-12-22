"""
Tests for authentication and authorization
"""
import pytest
from datetime import datetime, timedelta
import jwt
from valtdb.auth import User, AuthManager, RBAC, Permission, Role
from valtdb.exceptions import ValtDBError

@pytest.fixture
def auth_manager():
    return AuthManager("test_secret_key")

@pytest.fixture
def rbac():
    return RBAC()

def test_user_creation():
    user = User.create("testuser", "password123", ["user"])
    assert user.username == "testuser"
    assert user.roles == ["user"]
    assert user.verify_password("password123")
    assert not user.verify_password("wrongpass")

def test_user_serialization():
    user = User.create("testuser", "password123", ["user"])
    user_dict = user.to_dict()
    restored_user = User.from_dict(user_dict)
    assert restored_user.username == user.username
    assert restored_user.roles == user.roles
    assert restored_user.password_hash == user.password_hash

def test_auth_manager_user_management(auth_manager):
    # Add user
    user = auth_manager.add_user("testuser", "password123", ["user"])
    assert "testuser" in auth_manager.users
    
    # Duplicate user
    with pytest.raises(ValtDBError):
        auth_manager.add_user("testuser", "password456")
    
    # Remove user
    auth_manager.remove_user("testuser")
    assert "testuser" not in auth_manager.users
    
    # Remove non-existent user
    with pytest.raises(ValtDBError):
        auth_manager.remove_user("nonexistent")

def test_auth_manager_authentication(auth_manager):
    auth_manager.add_user("testuser", "password123", ["user"])
    
    # Successful authentication
    token = auth_manager.authenticate("testuser", "password123")
    assert token is not None
    
    # Failed authentication
    assert auth_manager.authenticate("testuser", "wrongpass") is None
    assert auth_manager.authenticate("nonexistent", "password123") is None

def test_auth_manager_token_verification(auth_manager):
    auth_manager.add_user("testuser", "password123", ["user"])
    token = auth_manager.authenticate("testuser", "password123")
    
    # Valid token
    payload = auth_manager.verify_token(token)
    assert payload is not None
    assert payload["sub"] == "testuser"
    assert payload["roles"] == ["user"]
    
    # Invalid token
    assert auth_manager.verify_token("invalid.token.here") is None
    
    # Blacklisted token
    auth_manager.invalidate_token(token)
    assert auth_manager.verify_token(token) is None

def test_auth_manager_role_checking(auth_manager):
    auth_manager.add_user("testuser", "password123", ["user", "admin"])
    token = auth_manager.authenticate("testuser", "password123")
    
    assert auth_manager.has_role(token, "user")
    assert auth_manager.has_role(token, "admin")
    assert not auth_manager.has_role(token, "superadmin")

def test_rbac_permission_management(rbac):
    # Add permissions
    read_perm = rbac.add_permission("read", "Read permission")
    write_perm = rbac.add_permission("write", "Write permission")
    
    assert "read" in rbac.permissions
    assert "write" in rbac.permissions
    
    # Duplicate permission
    with pytest.raises(ValtDBError):
        rbac.add_permission("read")

def test_rbac_role_management(rbac):
    rbac.add_permission("read")
    rbac.add_permission("write")
    
    # Add role
    role = rbac.add_role("editor", ["read", "write"])
    assert "editor" in rbac.roles
    assert len(role.permissions) == 2
    
    # Duplicate role
    with pytest.raises(ValtDBError):
        rbac.add_role("editor")
    
    # Invalid permission
    with pytest.raises(ValtDBError):
        rbac.add_role("invalid", ["nonexistent"])
    
    # Remove role
    rbac.remove_role("editor")
    assert "editor" not in rbac.roles

def test_rbac_permission_granting(rbac):
    rbac.add_permission("read")
    rbac.add_permission("write")
    rbac.add_role("viewer", ["read"])
    
    # Grant permission
    rbac.grant_permission("viewer", "write")
    assert rbac.roles["viewer"].has_permission("write")
    
    # Invalid role
    with pytest.raises(ValtDBError):
        rbac.grant_permission("nonexistent", "read")
    
    # Invalid permission
    with pytest.raises(ValtDBError):
        rbac.grant_permission("viewer", "nonexistent")

def test_rbac_permission_revoking(rbac):
    rbac.add_permission("read")
    rbac.add_permission("write")
    rbac.add_role("editor", ["read", "write"])
    
    # Revoke permission
    rbac.revoke_permission("editor", "write")
    assert not rbac.roles["editor"].has_permission("write")
    assert rbac.roles["editor"].has_permission("read")
    
    # Invalid role
    with pytest.raises(ValtDBError):
        rbac.revoke_permission("nonexistent", "read")

def test_expired_token(auth_manager):
    auth_manager.add_user("testuser", "password123", ["user"])
    
    # Create token with short expiration
    payload = {
        "sub": "testuser",
        "roles": ["user"],
        "exp": datetime.utcnow() - timedelta(hours=1)
    }
    token = jwt.encode(payload, auth_manager.secret_key, algorithm="HS256")
    
    # Verify expired token
    assert auth_manager.verify_token(token) is None
