"""
SSH support for ValtDB
"""
import os
import re
import shlex
import paramiko
from typing import Optional, Dict, Any, Tuple
from pathlib import Path
from .exceptions import ValtDBError

class SSHConfig:
    def __init__(
        self,
        hostname: str,
        username: str,
        port: int = 22,
        password: Optional[str] = None,
        key_filename: Optional[str] = None,
        passphrase: Optional[str] = None,
        timeout: int = 30
    ):
        self.hostname = hostname
        self.username = username
        self.port = port
        self.password = password
        self.key_filename = key_filename
        self.passphrase = passphrase
        self.timeout = timeout

    @classmethod
    def from_dict(cls, config: Dict[str, Any]) -> 'SSHConfig':
        """Create SSH config from dictionary"""
        return cls(**config)

    def to_dict(self) -> Dict[str, Any]:
        """Convert SSH config to dictionary"""
        return {
            "hostname": self.hostname,
            "username": self.username,
            "port": self.port,
            "password": self.password,
            "key_filename": self.key_filename,
            "passphrase": self.passphrase,
            "timeout": self.timeout
        }

class SSHClient:
    def __init__(self, config: SSHConfig):
        self.config = config
        self._client: Optional[paramiko.SSHClient] = None

    def connect(self):
        """Establish SSH connection with host key verification"""
        if self._client is not None:
            return

        try:
            self._client = paramiko.SSHClient()
            self._client.load_system_host_keys()
            known_hosts = os.path.expanduser('~/.ssh/known_hosts')
            if os.path.exists(known_hosts):
                self._client.load_host_keys(known_hosts)

            connect_kwargs = {
                "hostname": self.config.hostname,
                "username": self.config.username,
                "port": self.config.port,
                "timeout": self.config.timeout
            }

            if self.config.password:
                connect_kwargs["password"] = self.config.password
            elif self.config.key_filename:
                key_path = Path(self.config.key_filename).expanduser()
                if not key_path.exists():
                    raise ValtDBError(f"SSH key file not found: {key_path}")
                connect_kwargs["key_filename"] = str(key_path)
                if self.config.passphrase:
                    connect_kwargs["passphrase"] = self.config.passphrase
            else:
                # Try to use default SSH key
                default_key = Path("~/.ssh/id_rsa").expanduser()
                if default_key.exists():
                    connect_kwargs["key_filename"] = str(default_key)
                else:
                    raise ValtDBError("No authentication method provided")

            self._client.connect(**connect_kwargs)

        except paramiko.AuthenticationException:
            raise ValtDBError("SSH authentication failed")
        except paramiko.SSHException as e:
            raise ValtDBError(f"SSH connection error: {str(e)}")
        except Exception as e:
            raise ValtDBError(f"Failed to establish SSH connection: {str(e)}")

    def disconnect(self):
        """Close SSH connection"""
        if self._client:
            self._client.close()
            self._client = None

    def execute_command(self, command: str) -> Tuple[str, str, int]:
        """Execute command over SSH with input sanitization"""
        if not self._client:
            self.connect()

        # Sanitize command input
        if not self._is_safe_command(command):
            raise ValtDBError("Command contains unsafe characters")

        # Split command into arguments and escape them
        args = shlex.split(command)
        safe_command = " ".join(shlex.quote(arg) for arg in args)

        try:
            stdin, stdout, stderr = self._client.exec_command(safe_command)
            exit_status = stdout.channel.recv_exit_status()
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            return output, error, exit_status
        except paramiko.SSHException as e:
            raise ValtDBError(f"Failed to execute command: {str(e)}")
        except Exception as e:
            raise ValtDBError(f"Failed to execute command: {str(e)}")

    def upload_file(self, local_path: str, remote_path: str):
        """Upload file using SFTP"""
        if not self._client:
            self.connect()

        try:
            sftp = self._client.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
        except Exception as e:
            raise ValtDBError(f"Failed to upload file: {str(e)}")

    def download_file(self, remote_path: str, local_path: str):
        """Download file using SFTP"""
        if not self._client:
            self.connect()

        try:
            sftp = self._client.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
        except Exception as e:
            raise ValtDBError(f"Failed to download file: {str(e)}")

    def _is_safe_command(self, command: str) -> bool:
        """Check if command contains unsafe characters or patterns"""
        # List of unsafe patterns
        unsafe_patterns = [
            r'[|&;$]',  # Shell metacharacters
            r'`',       # Backticks
            r'>',       # Redirections
            r'<',
            r'\$\(',    # Command substitution
            r'\$\{',    # Variable expansion
            r'\\',      # Escapes
            r'[\n\r]'   # Newlines
        ]

        # Check for unsafe patterns
        for pattern in unsafe_patterns:
            if re.search(pattern, command):
                return False

        return True

    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()

class RemoteDatabase:
    def __init__(self, ssh_config: SSHConfig, db_path: str):
        self.ssh_config = ssh_config
        self.db_path = db_path
        self.ssh_client = SSHClient(ssh_config)

    def execute_query(self, query: str) -> Tuple[str, str, int]:
        """Execute query on remote database"""
        command = f'valtdb-cli query "{self.db_path}" "{query}"'
        return self.ssh_client.execute_command(command)

    def backup(self, local_path: str):
        """Backup remote database to local file"""
        self.ssh_client.download_file(self.db_path, local_path)

    def restore(self, local_path: str):
        """Restore remote database from local file"""
        self.ssh_client.upload_file(local_path, self.db_path)

    def __enter__(self):
        """Context manager entry"""
        self.ssh_client.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.ssh_client.disconnect()
