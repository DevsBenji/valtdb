"""
SSH connection management for ValtDB.
"""

import os
import re
import shlex
from typing import Optional, Tuple, List
import paramiko
from paramiko.client import SSHClient
from paramiko.config import SSH_PORT

class SSHConnection:
    """Manages SSH connections for remote database operations."""
    
    def __init__(self, 
                 hostname: str, 
                 username: str,
                 password: Optional[str] = None,
                 key_filename: Optional[str] = None,
                 port: int = SSH_PORT):
        """Initialize SSH connection.
        
        Args:
            hostname: Remote host to connect to
            username: Username for authentication
            password: Password for authentication (optional)
            key_filename: Path to private key file (optional)
            port: SSH port number (default: 22)
        """
        self.hostname = hostname
        self.username = username
        self.password = password
        self.key_filename = key_filename
        self.port = port
        self._client: Optional[SSHClient] = None
        
    def connect(self) -> None:
        """Establish SSH connection with host key verification."""
        if not self._client:
            self._client = paramiko.SSHClient()
            
            # Load system host keys
            self._client.load_system_host_keys()
            
            # Verify host keys
            known_hosts = os.path.expanduser('~/.ssh/known_hosts')
            if os.path.exists(known_hosts):
                self._client.load_host_keys(known_hosts)
            
            try:
                self._client.connect(
                    hostname=self.hostname,
                    username=self.username,
                    password=self.password,
                    key_filename=self.key_filename,
                    port=self.port
                )
            except paramiko.SSHException as e:
                raise ConnectionError(f"Failed to connect to {self.hostname}: {str(e)}")
            
    def disconnect(self) -> None:
        """Close SSH connection."""
        if self._client:
            self._client.close()
            self._client = None
            
    def execute_command(self, command: str) -> Tuple[int, str, str]:
        """Execute command on remote host with input sanitization.
        
        Args:
            command: Command to execute
            
        Returns:
            Tuple containing:
                - Exit status (int)
                - stdout output (str)
                - stderr output (str)
                
        Raises:
            ValueError: If command contains unsafe characters
            ConnectionError: If SSH connection fails
        """
        if not self._client:
            raise ConnectionError("Not connected to SSH server")
            
        # Sanitize command input
        if not self._is_safe_command(command):
            raise ValueError("Command contains unsafe characters")
            
        # Split command into arguments and escape them
        try:
            args = shlex.split(command)
        except ValueError as e:
            raise ValueError(f"Invalid command format: {str(e)}")
            
        # Validate each argument
        for arg in args:
            if not self._is_safe_argument(arg):
                raise ValueError(f"Unsafe argument: {arg}")
                
        # Build safe command with proper escaping
        safe_command = " ".join(shlex.quote(arg) for arg in args)
        
        try:
            # Use get_transport().open_session() for better security
            session = self._client.get_transport().open_session()
            session.exec_command(safe_command)  # nosec B601 - command is properly sanitized above
            
            # Get output
            stdout = session.makefile('rb', -1).read().decode('utf-8')
            stderr = session.makefile_stderr('rb', -1).read().decode('utf-8')
            exit_status = session.recv_exit_status()
            
            return exit_status, stdout, stderr
            
        except paramiko.SSHException as e:
            raise ConnectionError(f"Failed to execute command: {str(e)}")
        finally:
            if 'session' in locals():
                session.close()
            
    def _is_safe_command(self, command: str) -> bool:
        """Check if command contains unsafe characters or patterns.
        
        Args:
            command: Command to check
            
        Returns:
            bool: True if command is safe, False otherwise
        """
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
        
    def _is_safe_argument(self, arg: str) -> bool:
        """Check if command argument is safe.
        
        Args:
            arg: Argument to check
            
        Returns:
            bool: True if argument is safe, False otherwise
        """
        # List of unsafe argument patterns
        unsafe_patterns = [
            r'^-',      # Arguments starting with dash
            r'[<>|&]',  # Redirections and pipes
            r'\$',      # Variable expansion
            r'`',       # Command substitution
            r';',       # Command separator
            r'\\',      # Escapes
            r'[\n\r]'   # Newlines
        ]
        
        # Check for unsafe patterns
        for pattern in unsafe_patterns:
            if re.search(pattern, arg):
                return False
                
        # Check for relative or absolute paths
        if '/' in arg or '\\' in arg:
            return False
                
        return True
            
    def __enter__(self) -> 'SSHConnection':
        """Context manager entry."""
        self.connect()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.disconnect()
