"""
SSH connection and remote database management.
"""

import os
import re
import shlex
from typing import Any, Dict, List, Optional, Tuple

import paramiko
from paramiko.client import SSHClient

from .database import Database
from .exceptions import SSHError

# Default SSH port
SSH_PORT = 22

class SSHConfig:
    """SSH configuration."""
    def __init__(
        self,
        hostname: str,
        username: str,
        password: Optional[str] = None,
        key_filename: Optional[str] = None,
        port: int = SSH_PORT
    ):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.key_filename = key_filename
        self.port = port

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "hostname": self.hostname,
            "username": self.username,
            "password": self.password,
            "key_filename": self.key_filename,
            "port": self.port
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SSHConfig":
        """Create config from dictionary."""
        return cls(
            hostname=data["hostname"],
            username=data["username"],
            password=data.get("password"),
            key_filename=data.get("key_filename"),
            port=data.get("port", SSH_PORT)
        )


class SSHConnection:
    """Manages SSH connections."""
    def __init__(self, config: SSHConfig):
        self.config = config
        self._client: Optional[SSHClient] = None
        self._transport: Optional[paramiko.Transport] = None

    def connect(self) -> None:
        """Connect to SSH server."""
        try:
            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs: Dict[str, Any] = {
                'hostname': self.config.hostname,
                'username': self.config.username,
                'port': self.config.port
            }
            
            if self.config.password:
                connect_kwargs['password'] = self.config.password
            if self.config.key_filename:
                connect_kwargs['key_filename'] = self.config.key_filename

            self._client.connect(**connect_kwargs)
            self._transport = self._client.get_transport()
            if self._transport is None:
                raise SSHError("Failed to get transport")
        except paramiko.SSHException as e:
            raise SSHError(f"Failed to connect: {str(e)}")

    def close(self) -> None:
        """Close SSH connection."""
        if self._transport:
            self._transport.close()
        if self._client:
            self._client.close()
        self._transport = None

    def exec_command(self, command: str) -> Tuple[str, str]:
        """Execute command on remote server."""
        if not self._transport:
            raise SSHError("Not connected to SSH server")

        try:
            session = self._transport.open_session()
            session.exec_command(command)
            
            stdout_bytes = session.makefile('rb').read()
            stderr_bytes = session.makefile_stderr('rb').read()
            
            stdout = stdout_bytes.decode('utf-8')
            stderr = stderr_bytes.decode('utf-8')
            
            return stdout, stderr
        except paramiko.SSHException as e:
            raise SSHError(f"Failed to execute command: {str(e)}")


class RemoteDatabase(Database):
    """Remote database connection."""
    def __init__(self, config: SSHConfig, remote_path: str, local_path: Optional[str] = None):
        super().__init__(remote_path)
        self.config = config
        self.remote_path = remote_path
        self.local_path = local_path or remote_path
        self._ssh = SSHConnection(config)

    def connect(self) -> None:
        """Establish SSH connection."""
        self._ssh.connect()
        # Additional connection and database preparation logic

    def sync(self):
        """Synchronize remote database with local cache."""
        # Implement file transfer logic using SFTP
        pass

    def close(self) -> None:
        """Close SSH connection."""
        self._ssh.close()
        super().close()

    def execute_query(self, query: str) -> Tuple[str, str, int]:
        """Execute query on remote database."""
        stdout, stderr = self._ssh.exec_command(
            f'valtdb-cli query "{self.remote_path}" "{query}"'
        )
        return stdout, stderr, 0  # Return status code
