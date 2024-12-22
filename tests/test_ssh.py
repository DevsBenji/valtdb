"""
Tests for SSH functionality
"""

import unittest
from unittest.mock import Mock, patch
from valtdb.ssh import SSHConnection, SSHConfig, SSHError, RemoteDatabase
from valtdb.exceptions import ValtDBError

class TestSSH(unittest.TestCase):
    def setUp(self):
        self.config = SSHConfig(
            hostname="test.example.com",
            username="testuser",
            password="testpass",
            port=22
        )

    @patch('paramiko.SSHClient')
    def test_connect(self, mock_ssh):
        client = SSHConnection(self.config)
        client.connect()
        
        mock_ssh.return_value.connect.assert_called_once_with(
            hostname=self.config.hostname,
            username=self.config.username,
            password=self.config.password,
            key_filename=None,
            port=self.config.port
        )

    @patch('paramiko.SSHClient')
    def test_execute_command(self, mock_ssh):
        mock_transport = Mock()
        mock_session = Mock()
        mock_session.makefile.return_value.read.return_value = b"stdout"
        mock_session.makefile_stderr.return_value.read.return_value = b"stderr"
        mock_transport.open_session.return_value = mock_session
        mock_ssh.return_value.get_transport.return_value = mock_transport

        client = SSHConnection(self.config)
        client.connect()
        stdout, stderr = client.exec_command("ls")

        self.assertEqual(stdout, "stdout")
        self.assertEqual(stderr, "stderr")
        mock_session.exec_command.assert_called_once_with("ls")

    @patch('paramiko.SSHClient')
    def test_close(self, mock_ssh):
        client = SSHConnection(self.config)
        client.connect()
        client.close()
        
        mock_ssh.return_value.close.assert_called_once()

    def test_ssh_config(self):
        config_dict = self.config.to_dict()
        restored_config = SSHConfig.from_dict(config_dict)
        
        self.assertEqual(restored_config.hostname, self.config.hostname)
        self.assertEqual(restored_config.username, self.config.username)
        self.assertEqual(restored_config.password, self.config.password)
        self.assertEqual(restored_config.port, self.config.port)

    @patch('paramiko.SSHClient')
    def test_connection_failure(self, mock_ssh):
        mock_ssh.return_value.connect.side_effect = Exception("Connection failed")
        
        client = SSHConnection(self.config)
        with self.assertRaises(SSHError):
            client.connect()

    @patch('paramiko.SSHClient')
    def test_command_failure(self, mock_ssh):
        mock_ssh.return_value.exec_command.side_effect = Exception("Command failed")
        
        client = SSHConnection(self.config)
        with self.assertRaises(SSHError):
            client.exec_command("test command")

    def test_remote_database(self):
        db = RemoteDatabase(self.config, "/path/to/db")
        self.assertEqual(db.remote_path, "/path/to/db")
        self.assertEqual(db.local_path, "/path/to/db")

    @patch('paramiko.SSHClient')
    def test_remote_database_query(self, mock_ssh):
        mock_transport = Mock()
        mock_session = Mock()
        mock_session.makefile.return_value.read.return_value = b"result"
        mock_session.makefile_stderr.return_value.read.return_value = b""
        mock_transport.open_session.return_value = mock_session
        mock_ssh.return_value.get_transport.return_value = mock_transport

        db = RemoteDatabase(self.config, "/path/to/db")
        db.connect()
        stdout, stderr, status = db.execute_query("SELECT * FROM table")
        
        self.assertEqual(stdout, "result")
        self.assertEqual(stderr, "")
        self.assertEqual(status, 0)

def test_ssh_config_creation():
    config = SSHConfig(hostname="test.server.com", username="testuser", password="testpass")
    assert config.hostname == "test.server.com"
    assert config.username == "testuser"
    assert config.password == "testpass"
    assert config.port == 22  # default port

def test_ssh_config_serialization():
    config = SSHConfig(hostname="test.server.com", username="testuser", password="testpass")
    config_dict = config.to_dict()
    restored_config = SSHConfig.from_dict(config_dict)
    assert restored_config.hostname == config.hostname
    assert restored_config.username == config.username
    assert restored_config.password == config.password

def test_ssh_client_connection_failure():
    config = SSHConfig(hostname="test.server.com", username="testuser", password="testpass")
    client = SSHConnection(config)
    with unittest.TestCase().assertRaises(SSHError):
        client.connect()

def test_ssh_client_command_failure():
    config = SSHConfig(hostname="test.server.com", username="testuser", password="testpass")
    client = SSHConnection(config)
    with unittest.TestCase().assertRaises(SSHError):
        client.exec_command("test command")

def test_remote_database_operations():
    config = SSHConfig(hostname="test.server.com", username="testuser", password="testpass")
    db = RemoteDatabase(config, "/path/to/db")
    assert db.remote_path == "/path/to/db"
    assert db.local_path == "/path/to/db"
