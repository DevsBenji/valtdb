"""
Tests for SSH functionality
"""

from unittest.mock import Mock, patch

import pytest

from valtdb.exceptions import ValtDBError
from valtdb.ssh import RemoteDatabase, SSHClient, SSHConfig


@pytest.fixture
def ssh_config():
    return SSHConfig(hostname="test.server.com", username="testuser", password="testpass")


@pytest.fixture
def mock_paramiko_client():
    with patch("paramiko.SSHClient") as mock_client:
        client_instance = Mock()
        mock_client.return_value = client_instance
        yield client_instance


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


def test_ssh_client_connection(ssh_config, mock_paramiko_client):
    client = SSHClient(ssh_config)
    client.connect()
    mock_paramiko_client.connect.assert_called_once_with(
        hostname="test.server.com", username="testuser", password="testpass", port=22, timeout=30
    )


def test_ssh_client_command_execution(ssh_config, mock_paramiko_client):
    mock_channel = Mock()
    mock_channel.recv_exit_status.return_value = 0

    mock_stdout = Mock()
    mock_stdout.channel = mock_channel
    mock_stdout.read.return_value = b"command output"

    mock_stderr = Mock()
    mock_stderr.read.return_value = b""

    mock_paramiko_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

    client = SSHClient(ssh_config)
    output, error, status = client.execute_command("test command")

    assert output == "command output"
    assert error == ""
    assert status == 0
    mock_paramiko_client.exec_command.assert_called_once_with("test command")


def test_ssh_client_file_transfer(ssh_config, mock_paramiko_client):
    mock_sftp = Mock()
    mock_paramiko_client.open_sftp.return_value = mock_sftp

    client = SSHClient(ssh_config)
    client.upload_file("local.txt", "remote.txt")

    mock_sftp.put.assert_called_once_with("local.txt", "remote.txt")
    mock_sftp.close.assert_called_once()


def test_ssh_client_context_manager(ssh_config, mock_paramiko_client):
    with SSHClient(ssh_config) as client:
        assert client._client is not None
    mock_paramiko_client.close.assert_called_once()


def test_remote_database_operations(ssh_config, mock_paramiko_client):
    mock_channel = Mock()
    mock_channel.recv_exit_status.return_value = 0

    mock_stdout = Mock()
    mock_stdout.channel = mock_channel
    mock_stdout.read.return_value = b'{"result": "success"}'

    mock_stderr = Mock()
    mock_stderr.read.return_value = b""

    mock_paramiko_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

    db = RemoteDatabase(ssh_config, "/path/to/db")
    output, error, status = db.execute_query("SELECT * FROM users")

    assert output == '{"result": "success"}'
    assert status == 0
    mock_paramiko_client.exec_command.assert_called_once_with(
        'valtdb-cli query "/path/to/db" "SELECT * FROM users"'
    )


def test_ssh_client_connection_failure(ssh_config, mock_paramiko_client):
    mock_paramiko_client.connect.side_effect = Exception("Connection failed")

    client = SSHClient(ssh_config)
    with pytest.raises(ValtDBError) as exc_info:
        client.connect()
    assert "Failed to establish SSH connection" in str(exc_info.value)


def test_ssh_client_command_failure(ssh_config, mock_paramiko_client):
    mock_paramiko_client.exec_command.side_effect = Exception("Command failed")

    client = SSHClient(ssh_config)
    with pytest.raises(ValtDBError) as exc_info:
        client.execute_command("test command")
    assert "Failed to execute command" in str(exc_info.value)
