from unittest.mock import MagicMock, patch

import pytest

from app.services.ssh.bootstrap import bootstrap_server_access


@pytest.fixture
def valid_public_key():
    return (
        "ssh-rsa "
        "AAAAB3NzaC1yc2EAAAADAQABAAABAQDGh6W/2E6fJ6jGq9mJtU+9W0Yj6s4FQw0n"
        "P8QqvYf1J2WJY8kq1m1Ff9m8H3Q2P4L6QdK3mJxg4Q7fX0Jq3V4vV4C6Y3cM4dM1"
        "Y9K2x2P7v3cE8w9R0lM5sQ2pN7aK1mT5jV8fA3dL9kP2mR6sW0qY3vT6bN1pL8zR4"
        "xC7vH2qF5mJ9nK3pD6wT1bV4eN7qR0xM3sZ6cP9vB2nH5jK8mL1q "
        "test@example.com"
    )


@pytest.fixture
def private_key():
    return "-----BEGIN OPENSSH PRIVATE KEY-----\nkey-data\n-----END OPENSSH PRIVATE KEY-----"


class TestBootstrapServerAccess:
    @patch("app.services.ssh.bootstrap.validate_ssh_public_key", return_value=True)
    @patch("app.services.ssh.bootstrap.SSHConnection")
    def test_root_bootstrap_success(
        self, mock_connection_class, _mock_validate_key, valid_public_key, private_key
    ):
        password_connection = MagicMock()
        password_connection.connect_with_password.return_value = (True, None)
        password_connection.execute.side_effect = [
            (True, "", ""),
            (True, "", ""),
            (True, "", ""),
        ]

        verification_connection = MagicMock()
        verification_connection.connect_with_key.return_value = (True, None)
        verification_connection.execute.return_value = (True, "ok", "")

        mock_connection_class.side_effect = [password_connection, verification_connection]

        result = bootstrap_server_access(
            host="192.0.2.10",
            port=22,
            bootstrap_username="root",
            password="secret",
            public_key=valid_public_key,
            private_key=private_key,
            requires_legacy_ssh=False,
            openssh_version="9.6",
        )

        assert result["success"] is True
        assert result["verified"] is True
        assert result["target_username"] == "root"
        assert any(
            "/root/.ssh" in call.args[0] for call in password_connection.execute.call_args_list
        )
        assert mock_connection_class.call_args_list[1].args == ("192.0.2.10", 22, "root")

    @patch("app.services.ssh.bootstrap.validate_ssh_public_key", return_value=True)
    @patch("app.services.ssh.bootstrap.SSHConnection")
    def test_sudo_user_bootstrap_success(
        self, mock_connection_class, _mock_validate_key, valid_public_key, private_key
    ):
        password_connection = MagicMock()
        password_connection.connect_with_password.return_value = (True, None)
        password_connection.execute.side_effect = [
            (True, "", ""),
            (True, "", ""),
            (True, "", ""),
            (True, "", ""),
        ]

        verification_connection = MagicMock()
        verification_connection.connect_with_key.return_value = (True, None)
        verification_connection.execute.return_value = (True, "ok", "")

        mock_connection_class.side_effect = [password_connection, verification_connection]

        result = bootstrap_server_access(
            host="192.0.2.20",
            port=22,
            bootstrap_username="admin",
            password="secret",
            public_key=valid_public_key,
            private_key=private_key,
            requires_legacy_ssh=False,
            openssh_version="9.6",
        )

        assert result["success"] is True
        assert result["target_username"] == "root"
        assert any(
            "sudo -n sh -c" in call.args[0] and "/root/.ssh" in call.args[0]
            for call in password_connection.execute.call_args_list
        )
        assert mock_connection_class.call_args_list[0].args == ("192.0.2.20", 22, "admin")
        assert mock_connection_class.call_args_list[1].args == ("192.0.2.20", 22, "root")

    @patch("app.services.ssh.bootstrap.validate_ssh_public_key", return_value=True)
    @patch("app.services.ssh.bootstrap.SSHConnection")
    def test_no_sudo_fails(
        self, mock_connection_class, _mock_validate_key, valid_public_key, private_key
    ):
        password_connection = MagicMock()
        password_connection.connect_with_password.return_value = (True, None)
        password_connection.execute.side_effect = [
            (False, "", "sudo unavailable"),
            (False, "", "sudo password rejected"),
        ]
        mock_connection_class.return_value = password_connection

        result = bootstrap_server_access(
            host="192.0.2.30",
            port=22,
            bootstrap_username="admin",
            password="secret",
            public_key=valid_public_key,
            private_key=private_key,
            requires_legacy_ssh=False,
            openssh_version="9.6",
        )

        assert result["success"] is False
        assert result["error_type"] == "root_access_unavailable"
        assert "root/sudo" in str(result["message"])
        assert mock_connection_class.call_count == 1

    @patch("app.services.ssh.bootstrap.validate_ssh_public_key", return_value=True)
    @patch("app.services.ssh.bootstrap.SSHConnection")
    def test_remediation_sets_required_root_login_directives(
        self,
        mock_connection_class,
        _mock_validate_key,
        valid_public_key,
        private_key,
    ):
        password_connection = MagicMock()
        password_connection.connect_with_password.return_value = (True, None)
        password_connection.execute.side_effect = [
            (True, "", ""),
            (True, "", ""),
            (True, "", ""),
            (True, "", ""),
            (True, "/tmp/sshd_config.backup.1", ""),
            (
                True,
                (
                    "Include /etc/ssh/sshd_config.d/*.conf\n"
                    "PermitRootLogin no\n"
                    "PasswordAuthentication no\n"
                    "PubkeyAuthentication no\n"
                ),
                "",
            ),
            (True, "", ""),
            (True, "", ""),
            (True, "", ""),
        ]

        failed_verification_connection = MagicMock()
        failed_verification_connection.connect_with_key.return_value = (
            False,
            "Ошибка аутентификации: root key rejected",
        )

        successful_verification_connection = MagicMock()
        successful_verification_connection.connect_with_key.return_value = (True, None)
        successful_verification_connection.execute.return_value = (True, "ok", "")

        mock_connection_class.side_effect = [
            password_connection,
            failed_verification_connection,
            successful_verification_connection,
        ]

        result = bootstrap_server_access(
            host="192.0.2.40",
            port=22,
            bootstrap_username="admin",
            password="secret",
            public_key=valid_public_key,
            private_key=private_key,
            requires_legacy_ssh=False,
            openssh_version="9.6",
        )

        assert result["success"] is True
        assert result["remediated"] is True
        remediation_commands = [call.args[0] for call in password_connection.execute.call_args_list]
        write_commands = [
            command
            for command in remediation_commands
            if "cat > /etc/ssh/sshd_config <<" in command
        ]
        assert write_commands
        write_command = write_commands[0]
        assert "# Include /etc/ssh/sshd_config.d/*.conf" in write_command
        assert "PermitRootLogin yes" in write_command
        assert "PasswordAuthentication yes" in write_command
        assert "PubkeyAuthentication yes" in write_command
        assert "PubkeyAcceptedAlgorithms +ssh-rsa" in write_command
        assert "PubkeyAcceptedKeyTypes +ssh-rsa" in write_command

    @patch("app.services.ssh.bootstrap.validate_ssh_public_key", return_value=True)
    @patch("app.services.ssh.bootstrap.SSHConnection")
    def test_rolls_back_remediation_when_validation_fails(
        self,
        mock_connection_class,
        _mock_validate_key,
        valid_public_key,
        private_key,
    ):
        password_connection = MagicMock()
        password_connection.connect_with_password.return_value = (True, None)
        password_connection.execute.side_effect = [
            (True, "", ""),
            (True, "", ""),
            (True, "", ""),
            (True, "/tmp/sshd_config.backup.2", ""),
            (True, "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\n", ""),
            (False, "", "Bad configuration option"),
            (True, "", ""),
            (True, "", ""),
        ]

        verification_connection = MagicMock()
        verification_connection.connect_with_key.return_value = (
            False,
            "Ошибка аутентификации: key rejected",
        )

        mock_connection_class.side_effect = [password_connection, verification_connection]

        result = bootstrap_server_access(
            host="192.0.2.50",
            port=22,
            bootstrap_username="root",
            password="secret",
            public_key=valid_public_key,
            private_key=private_key,
            requires_legacy_ssh=False,
            openssh_version="9.6",
        )

        assert result["success"] is False
        assert result["error_type"] == "sshd_remediation_failed"
        assert any(
            "/tmp/sshd_config.backup.2" in call.args[0]
            for call in password_connection.execute.call_args_list
        )
