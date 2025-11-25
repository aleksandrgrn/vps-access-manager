from unittest.mock import MagicMock, patch

import pytest

# Импорт должен быть перед skip для корректной работы Flake8
# Однако pytest.skip прервет выполнение, поэтому этот импорт никогда не выполнится
try:
    from app.services.ssh.operations import deploy_key, revoke_key
except ImportError:
    pass

pytest.skip(
    "Модуль app.services.ssh.operations отсутствует в текущей версии", allow_module_level=True
)


@pytest.fixture
def mock_ssh_client():
    client = MagicMock()
    return client


@patch("app.services.ssh.operations.connect_with_adaptive_algorithms")
@patch("app.services.ssh.operations.validate_ssh_public_key")
@patch("paramiko.RSAKey.from_private_key")
@patch("flask.current_app", new_callable=MagicMock)
def test_deploy_key_success(
    mock_app, mock_rsa_key, mock_validate, mock_connect, mock_ssh_client, new_server, new_ssh_key
):
    """Test successful key deployment."""
    # Setup mocks
    mock_app.config.get.return_value = False  # Disable global mock for this test
    mock_validate.return_value = True
    mock_connect.return_value = mock_ssh_client
    mock_rsa_key.return_value = MagicMock()

    # Mock SFTP
    mock_sftp = MagicMock()
    mock_ssh_client.open_sftp.return_value = mock_sftp

    # Mock authorized_keys reading (file not found initially, then success for write)
    mock_file_handle = MagicMock()
    mock_sftp.open.side_effect = [FileNotFoundError, mock_file_handle]

    # Mock exec_command for mkdir
    stdout_mock = MagicMock()
    stdout_mock.channel.recv_exit_status.return_value = 0
    mock_ssh_client.exec_command.return_value = (None, stdout_mock, MagicMock())

    # Execute
    dummy_private_key = (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
    )

    success, message = deploy_key(
        new_server.ip_address,
        new_server.ssh_port,
        new_server.username,
        dummy_private_key,
        new_ssh_key.public_key,
        new_server,
    )

    # Verify
    assert success is True
    assert "успешно развернут" in message
    mock_connect.assert_called_once()
    mock_sftp.open.assert_called()  # Should try to open authorized_keys


@patch("app.services.ssh.operations.connect_with_adaptive_algorithms")
@patch("paramiko.RSAKey.from_private_key")
@patch("flask.current_app", new_callable=MagicMock)
def test_deploy_key_connection_failure(
    mock_app, mock_rsa_key, mock_connect, new_server, new_ssh_key
):
    """Test deployment connection failure."""
    # Setup mock to return None (connection failed)
    mock_app.config.get.return_value = False  # Disable global mock for this test
    mock_connect.return_value = None
    mock_rsa_key.return_value = MagicMock()

    dummy_private_key = (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
    )

    # Execute
    success, message = deploy_key(
        new_server.ip_address,
        new_server.ssh_port,
        new_server.username,
        dummy_private_key,
        new_ssh_key.public_key,
        new_server,
    )

    # Verify
    assert success is False
    # The actual error message might vary depending on how connect_with_adaptive_algorithms returns
    # But deploy_key checks "if not client: return False, ..."


@patch("app.services.ssh.operations.connect_with_adaptive_algorithms")
@patch("app.services.ssh.operations.validate_ssh_public_key")
@patch("paramiko.RSAKey.from_private_key")
@patch("flask.current_app", new_callable=MagicMock)
def test_revoke_key_success(
    mock_app, mock_rsa_key, mock_validate, mock_connect, mock_ssh_client, new_server, new_ssh_key
):
    """Test successful key revocation."""
    # Setup mocks
    mock_app.config.get.return_value = False  # Disable global mock for this test
    mock_validate.return_value = True
    mock_connect.return_value = mock_ssh_client
    mock_rsa_key.return_value = MagicMock()

    # Mock SFTP
    mock_sftp = MagicMock()
    mock_ssh_client.open_sftp.return_value = mock_sftp

    # Mock authorized_keys content
    content = (
        f"ssh-rsa AAAAB3NzaC1yc2E... old-key\n{new_ssh_key.public_key}\nssh-ed25519 ... another-key"
    )

    # Mock getfo (reading)
    def side_effect_getfo(remotepath, flo):
        flo.write(content.encode("utf-8"))
        flo.seek(0)

    mock_sftp.getfo.side_effect = side_effect_getfo

    dummy_private_key = (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
    )

    # Execute
    result = revoke_key(
        new_server.ip_address,
        new_server.ssh_port,
        new_server.username,
        dummy_private_key,
        new_ssh_key.public_key,
        new_server,
    )

    # Verify
    assert result["success"] is True
    assert "успешно удален" in result["message"]
    mock_sftp.putfo.assert_called()  # Should write back new content
