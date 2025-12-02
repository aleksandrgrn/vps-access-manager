"""
Тесты для модуля SSH Operations.
Проверяет функции развёртывания, отзыва и верификации ключей.
"""

from unittest.mock import MagicMock, Mock, patch

import pytest

from app.services.ssh.operations import (
    bulk_deploy_keys,
    deploy_key_to_server,
    revoke_key_from_server,
    verify_key_deployed,
)

# ==================== ФИКСТУРЫ ====================


@pytest.fixture
def mock_server():
    """Мок объекта сервера."""
    server = Mock()
    server.name = "test-server"
    server.ip_address = "192.168.1.100"
    server.ssh_port = 22
    server.username = "root"
    server.requires_legacy_ssh = False
    return server


@pytest.fixture
def valid_public_key():
    """Валидный публичный SSH ключ."""
    return "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC1234567890abcdef test@example.com"


@pytest.fixture
def mock_connection():
    """Мок SSH соединения."""
    conn = MagicMock()
    conn.execute = MagicMock()
    return conn


# ==================== ТЕСТЫ DEPLOY_KEY_TO_SERVER ====================


class TestDeployKeyToServer:
    """Тесты функции deploy_key_to_server."""

    @patch("app.services.ssh.operations.validate_ssh_public_key", return_value=True)
    def test_deploy_key_success(
        self, mock_validate, mock_server, valid_public_key, mock_connection
    ):
        """Успешное развёртывание ключа."""
        # Настройка моков
        mock_connection.execute.side_effect = [
            (True, "", ""),  # mkdir -p ~/.ssh
            (True, "", ""),  # cat authorized_keys (пустой файл)
            (True, "", ""),  # echo >> authorized_keys
        ]

        # Выполнение
        result = deploy_key_to_server(mock_server, valid_public_key, mock_connection)
        success = result["success"]
        message = result["message"]

        # Проверки
        assert success is True
        assert "успешно добавлен" in message.lower()
        assert mock_connection.execute.call_count == 3

    @patch("app.services.ssh.operations.validate_ssh_public_key", return_value=True)
    def test_deploy_key_already_exists(
        self, mock_validate, mock_server, valid_public_key, mock_connection
    ):
        """Ключ уже существует на сервере."""
        # Настройка моков
        mock_connection.execute.side_effect = [
            (True, "", ""),  # mkdir -p ~/.ssh
            (True, valid_public_key, ""),  # cat authorized_keys (ключ уже есть)
        ]

        # Выполнение
        result = deploy_key_to_server(mock_server, valid_public_key, mock_connection)
        success = result["success"]
        message = result["message"]

        # Проверки
        assert success is True
        assert "уже установлен" in message.lower()
        assert mock_connection.execute.call_count == 2

    def test_deploy_key_invalid_key(self, mock_server, mock_connection):
        """Попытка развернуть невалидный ключ."""
        invalid_key = "invalid-key-format"

        # Выполнение
        result = deploy_key_to_server(mock_server, invalid_key, mock_connection)
        success = result["success"]
        message = result["message"]

        # Проверки
        assert success is False
        assert "невалидный" in message.lower()
        mock_connection.execute.assert_not_called()

    @patch("app.services.ssh.operations.validate_ssh_public_key", return_value=True)
    def test_deploy_key_mkdir_fails(
        self, mock_validate, mock_server, valid_public_key, mock_connection
    ):
        """Ошибка при создании директории .ssh."""
        # Настройка моков
        mock_connection.execute.return_value = (False, "", "Permission denied")

        # Выполнение
        result = deploy_key_to_server(mock_server, valid_public_key, mock_connection)
        success = result["success"]
        message = result["message"]

        # Проверки
        assert success is False
        assert "ошибка создания" in message.lower()

    @patch("app.services.ssh.operations.validate_ssh_public_key", return_value=True)
    def test_deploy_key_append_fails(
        self, mock_validate, mock_server, valid_public_key, mock_connection
    ):
        """Ошибка при добавлении ключа в authorized_keys."""
        # Настройка моков
        mock_connection.execute.side_effect = [
            (True, "", ""),  # mkdir успешно
            (True, "", ""),  # cat успешно (ключа нет)
            (False, "", "Disk full"),  # echo fails
        ]

        # Выполнение
        result = deploy_key_to_server(mock_server, valid_public_key, mock_connection)
        success = result["success"]
        message = result["message"]

        # Проверки
        assert success is False
        assert "ошибка добавления" in message.lower()


# ==================== ТЕСТЫ REVOKE_KEY_FROM_SERVER ====================


class TestRevokeKeyFromServer:
    """Тесты функции revoke_key_from_server."""

    @patch("app.services.ssh.operations.validate_ssh_public_key", return_value=True)
    def test_revoke_key_success(
        self, mock_validate, mock_server, valid_public_key, mock_connection
    ):
        """Успешный отзыв ключа."""
        # Настройка моков
        authorized_keys_content = f"{valid_public_key}\nssh-rsa AAAAB3NzaC2 another@key.com"
        mock_connection.execute.side_effect = [
            (True, "", ""),  # cp backup
            (True, authorized_keys_content, ""),  # cat authorized_keys
            (True, "", ""),  # echo > authorized_keys (обновление)
        ]

        # Выполнение
        result = revoke_key_from_server(mock_server, valid_public_key, mock_connection)
        success = result["success"]
        message = result["message"]

        # Проверки
        assert success is True
        assert "успешно отозван" in message.lower()

    @patch("app.services.ssh.operations.validate_ssh_public_key", return_value=True)
    def test_revoke_key_not_found(
        self, mock_validate, mock_server, valid_public_key, mock_connection
    ):
        """Ключ не найден в authorized_keys."""
        # Настройка моков
        authorized_keys_content = "ssh-rsa AAAAB3NzaC2 another@key.com"
        mock_connection.execute.side_effect = [
            (True, "", ""),  # cp backup
            (True, authorized_keys_content, ""),  # cat authorized_keys
        ]

        # Выполнение
        result = revoke_key_from_server(mock_server, valid_public_key, mock_connection)
        success = result["success"]
        message = result["message"]

        # Проверки
        assert success is False
        assert "не найден" in message.lower()

    def test_revoke_key_invalid_key(self, mock_server, mock_connection):
        """Попытка отозвать невалидный ключ."""
        invalid_key = "invalid-key-format"

        # Выполнение
        result = revoke_key_from_server(mock_server, invalid_key, mock_connection)
        success = result["success"]
        message = result["message"]

        # Проверки
        assert success is False
        assert "невалидный" in message.lower()

    @patch("app.services.ssh.operations.validate_ssh_public_key", return_value=True)
    def test_revoke_key_write_fails_with_restore(
        self, mock_validate, mock_server, valid_public_key, mock_connection
    ):
        """Ошибка записи с восстановлением из backup."""
        # Настройка моков
        authorized_keys_content = f"{valid_public_key}\n"
        mock_connection.execute.side_effect = [
            (True, "", ""),  # cp backup успешно
            (True, authorized_keys_content, ""),  # cat успешно
            (False, "", "Write error"),  # echo fails
            (True, "", ""),  # mv backup restore
        ]

        # Выполнение
        result = revoke_key_from_server(mock_server, valid_public_key, mock_connection)
        success = result["success"]
        message = result["message"]

        # Проверки
        assert success is False
        assert "ошибка" in message.lower()


# ==================== ТЕСТЫ VERIFY_KEY_DEPLOYED ====================


class TestVerifyKeyDeployed:
    """Тесты функции verify_key_deployed."""

    @patch("app.services.ssh.operations.validate_ssh_public_key", return_value=True)
    def test_verify_key_exists(self, mock_validate, mock_server, valid_public_key, mock_connection):
        """Ключ найден на сервере."""
        # Настройка моков
        mock_connection.execute.return_value = (True, valid_public_key, "")

        # Выполнение
        result = verify_key_deployed(mock_server, valid_public_key, mock_connection)

        # Проверки
        assert result is True

    @patch("app.services.ssh.operations.validate_ssh_public_key", return_value=True)
    def test_verify_key_not_exists(
        self, mock_validate, mock_server, valid_public_key, mock_connection
    ):
        """Ключ не найден на сервере."""
        # Настройка моков
        mock_connection.execute.return_value = (True, "ssh-rsa AAAAB3NzaC2 other@key", "")

        # Выполнение
        result = verify_key_deployed(mock_server, valid_public_key, mock_connection)

        # Проверки
        assert result is False

    @patch("app.services.ssh.operations.validate_ssh_public_key", return_value=True)
    def test_verify_key_execute_fails(
        self, mock_validate, mock_server, valid_public_key, mock_connection
    ):
        """Ошибка выполнения команды."""
        # Настройка моков
        mock_connection.execute.return_value = (False, "", "Connection error")

        # Выполнение
        result = verify_key_deployed(mock_server, valid_public_key, mock_connection)

        # Проверки
        assert result is False


# ==================== ТЕСТЫ BULK_DEPLOY_KEYS ====================


class TestBulkDeployKeys:
    """Тесты функции bulk_deploy_keys."""

    @patch("app.services.ssh.operations.validate_ssh_public_key", return_value=True)
    @patch("app.services.ssh.operations.SSHConnection")
    def test_bulk_deploy_success(
        self, mock_ssh_connection_class, mock_validate, mock_server, valid_public_key
    ):
        """Успешное массовое развёртывание ключей."""
        # Настройка моков
        mock_conn = MagicMock()
        mock_conn.connect_with_key.return_value = (True, None)
        mock_conn.execute.side_effect = [
            (True, "", ""),  # mkdir
            (True, "", ""),  # cat
            (True, "", ""),  # echo
        ]
        mock_ssh_connection_class.return_value = mock_conn

        # Добавляем атрибут private_key для мок сервера
        mock_server.private_key = "test-private-key"

        servers = [mock_server]
        keys = [valid_public_key]

        # Выполнение
        results = bulk_deploy_keys(servers, keys)

        # Проверки
        assert results["total"] == 1
        assert len(results["deployed"]) == 1
        assert len(results["failed"]) == 0

    @patch("app.services.ssh.operations.validate_ssh_public_key", return_value=True)
    @patch("app.services.ssh.operations.SSHConnection")
    def test_bulk_deploy_connection_fails(
        self, mock_ssh_connection_class, mock_validate, mock_server, valid_public_key
    ):
        """Ошибка подключения при массовом развёртывании."""
        # Настройка моков
        mock_conn = MagicMock()
        mock_conn.connect_with_key.return_value = (False, "Connection timeout")
        mock_ssh_connection_class.return_value = mock_conn

        mock_server.private_key = "test-private-key"

        servers = [mock_server]
        keys = [valid_public_key]

        # Выполнение
        results = bulk_deploy_keys(servers, keys)

        # Проверки
        assert results["total"] == 1
        assert len(results["deployed"]) == 0
        assert len(results["failed"]) == 1
        assert "timeout" in results["failed"][0]["error"].lower()

    @patch("app.services.ssh.operations.validate_ssh_public_key", return_value=True)
    @patch("app.services.ssh.operations.SSHConnection")
    def test_bulk_deploy_multiple_servers(
        self, mock_ssh_connection_class, mock_validate, valid_public_key
    ):
        """Массовое развёртывание на несколько серверов."""
        # Настройка моков
        mock_conn = MagicMock()
        mock_conn.connect_with_key.return_value = (True, None)
        mock_conn.execute.side_effect = [
            (True, "", ""),  # mkdir server1
            (True, "", ""),  # cat server1
            (True, "", ""),  # echo server1
            (True, "", ""),  # mkdir server2
            (True, "", ""),  # cat server2
            (True, "", ""),  # echo server2
        ]
        mock_ssh_connection_class.return_value = mock_conn

        # Создаём 2 сервера
        server1 = Mock(
            name="server1",
            ip_address="192.168.1.1",
            ssh_port=22,
            username="root",
            private_key="key1",
        )
        server2 = Mock(
            name="server2",
            ip_address="192.168.1.2",
            ssh_port=22,
            username="root",
            private_key="key2",
        )

        servers = [server1, server2]
        keys = [valid_public_key]

        # Выполнение
        results = bulk_deploy_keys(servers, keys)

        # Проверки
        assert results["total"] == 2
        assert len(results["deployed"]) == 2
        assert len(results["failed"]) == 0
