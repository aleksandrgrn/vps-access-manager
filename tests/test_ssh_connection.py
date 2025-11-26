"""
Тесты для модуля SSH Connection.
Проверяет функциональность класса SSHConnection и вспомогательной функции ssh_connection.
"""

from unittest.mock import MagicMock, Mock, patch

import paramiko
import pytest

from app.services.ssh.connection import SSHConnection, ssh_connection

# ==================== ФИКСТУРЫ ====================


@pytest.fixture
def rsa_private_key():
    """Тестовый RSA приватный ключ."""
    return """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdef
-----END RSA PRIVATE KEY-----"""


@pytest.fixture
def ed25519_private_key():
    """Тестовый Ed25519 приватный ключ."""
    return """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAA
-----END OPENSSH PRIVATE KEY-----"""


@pytest.fixture
def mock_server_obj():
    """Мок объекта Server из БД."""
    server = Mock()
    server.requires_legacy_ssh = False
    server.openssh_version = "8.0"
    return server


@pytest.fixture
def mock_legacy_server_obj():
    """Мок legacy сервера (старый OpenSSH)."""
    server = Mock()
    server.requires_legacy_ssh = True
    server.openssh_version = "5.3"
    return server


# ==================== ТЕСТЫ ПОДКЛЮЧЕНИЯ ПО ПАРОЛЮ ====================


class TestSSHConnectionPassword:
    """Тесты подключения по паролю."""

    @patch("app.services.ssh.connection.paramiko.SSHClient")
    def test_connect_with_password_success(self, mock_ssh_client_class):
        """Успешное подключение по паролю."""
        # Настройка мока
        mock_client = MagicMock()
        mock_ssh_client_class.return_value = mock_client

        # Создание соединения
        conn = SSHConnection("192.168.1.1", 22, "root")
        success, error = conn.connect_with_password("secret_password")

        # Проверки
        assert success is True
        assert error is None
        assert conn.client is not None

        # Проверяем что вызвали connect с правильными параметрами
        mock_client.connect.assert_called_once()
        call_kwargs = mock_client.connect.call_args[1]
        assert call_kwargs["hostname"] == "192.168.1.1"
        assert call_kwargs["port"] == 22
        assert call_kwargs["username"] == "root"
        assert call_kwargs["password"] == "secret_password"
        assert call_kwargs["timeout"] == 15

    @patch("app.services.ssh.connection.paramiko.SSHClient")
    def test_connect_with_password_auth_fail(self, mock_ssh_client_class):
        """Ошибка аутентификации при подключении по паролю."""
        # Настройка мока — выбрасываем AuthenticationException
        mock_client = MagicMock()
        mock_client.connect.side_effect = paramiko.AuthenticationException("Auth failed")
        mock_ssh_client_class.return_value = mock_client

        # Создание соединения
        conn = SSHConnection("192.168.1.1", 22, "root")
        success, error = conn.connect_with_password("wrong_password")

        # Проверки
        assert success is False
        assert error is not None
        assert "аутентификации" in error.lower()

    @patch("app.services.ssh.connection.paramiko.SSHClient")
    def test_connect_with_password_ssh_exception(self, mock_ssh_client_class):
        """SSHException при подключении."""
        mock_client = MagicMock()
        mock_client.connect.side_effect = paramiko.SSHException("Connection error")
        mock_ssh_client_class.return_value = mock_client

        conn = SSHConnection("192.168.1.1", 22, "root")
        success, error = conn.connect_with_password("password")

        assert success is False
        assert "SSH" in error

    @patch("app.services.ssh.connection.paramiko.SSHClient")
    def test_connect_with_password_generic_exception(self, mock_ssh_client_class):
        """Неизвестная ошибка при подключении."""
        mock_client = MagicMock()
        mock_client.connect.side_effect = Exception("Unknown error")
        mock_ssh_client_class.return_value = mock_client

        conn = SSHConnection("192.168.1.1", 22, "root")
        success, error = conn.connect_with_password("password")

        assert success is False
        assert "Неизвестная ошибка" in error


# ==================== ТЕСТЫ ПОДКЛЮЧЕНИЯ ПО КЛЮЧУ ====================


class TestSSHConnectionKey:
    """Тесты подключения по SSH-ключу."""

    @patch("app.services.ssh.connection.paramiko.SSHClient")
    @patch("app.services.ssh.connection.paramiko.RSAKey")
    def test_connect_with_key_rsa_success(
        self, mock_rsa_key_class, mock_ssh_client_class, rsa_private_key
    ):
        """Успешное подключение по RSA-ключу."""
        # Настройка моков
        mock_pkey = MagicMock()
        mock_rsa_key_class.from_private_key.return_value = mock_pkey

        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_client_class.return_value = mock_client

        # Создание соединения
        conn = SSHConnection("192.168.1.1", 22, "root")
        success, error = conn.connect_with_key(rsa_private_key)

        # Проверки
        assert success is True
        assert error is None
        mock_rsa_key_class.from_private_key.assert_called_once()
        mock_client.connect.assert_called_once()

        # Проверяем параметры подключения
        call_kwargs = mock_client.connect.call_args[1]
        assert call_kwargs["hostname"] == "192.168.1.1"
        assert call_kwargs["pkey"] == mock_pkey

    @patch("app.services.ssh.connection.paramiko.SSHClient")
    @patch("app.services.ssh.connection.paramiko.Ed25519Key")
    def test_connect_with_key_ed25519_success(
        self, mock_ed25519_key_class, mock_ssh_client_class, ed25519_private_key
    ):
        """Успешное подключение по Ed25519-ключу."""
        # Настройка моков
        mock_pkey = MagicMock()
        mock_ed25519_key_class.from_private_key.return_value = mock_pkey

        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_client_class.return_value = mock_client

        # Создание соединения
        conn = SSHConnection("192.168.1.1", 22, "root")
        success, error = conn.connect_with_key(ed25519_private_key)

        # Проверки
        assert success is True
        assert error is None
        mock_ed25519_key_class.from_private_key.assert_called_once()

    @patch("app.services.ssh.connection.paramiko.SSHClient")
    @patch("app.services.ssh.connection.paramiko.RSAKey")
    def test_connect_with_key_legacy_ssh(
        self, mock_rsa_key_class, mock_ssh_client_class, rsa_private_key, mock_legacy_server_obj
    ):
        """Подключение к legacy OpenSSH серверу с отключенными новыми алгоритмами."""
        # Настройка моков
        mock_pkey = MagicMock()
        mock_rsa_key_class.from_private_key.return_value = mock_pkey

        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_client_class.return_value = mock_client

        # Создание соединения
        conn = SSHConnection("192.168.1.1", 22, "root")
        success, error = conn.connect_with_key(rsa_private_key, mock_legacy_server_obj)

        # Проверки
        assert success is True

        # Проверяем что disabled_algorithms был передан
        call_kwargs = mock_client.connect.call_args[1]
        assert "disabled_algorithms" in call_kwargs
        assert "pubkeys" in call_kwargs["disabled_algorithms"]
        assert "rsa-sha2-512" in call_kwargs["disabled_algorithms"]["pubkeys"]
        assert "rsa-sha2-256" in call_kwargs["disabled_algorithms"]["pubkeys"]

    @patch("app.services.ssh.connection.paramiko.SSHClient")
    @patch("app.services.ssh.connection.paramiko.RSAKey")
    def test_connect_with_key_auth_fail(
        self, mock_rsa_key_class, mock_ssh_client_class, rsa_private_key
    ):
        """Ошибка аутентификации при подключении по ключу."""
        mock_pkey = MagicMock()
        mock_rsa_key_class.from_private_key.return_value = mock_pkey

        mock_client = MagicMock()
        mock_client.connect.side_effect = paramiko.AuthenticationException("Key rejected")
        mock_ssh_client_class.return_value = mock_client

        conn = SSHConnection("192.168.1.1", 22, "root")
        success, error = conn.connect_with_key(rsa_private_key)

        assert success is False
        assert "аутентификации" in error.lower()


# ==================== ТЕСТЫ ВЫПОЛНЕНИЯ КОМАНД ====================


class TestSSHConnectionExecute:
    """Тесты выполнения команд через SSH."""

    def test_execute_command_success(self):
        """Успешное выполнение команды."""
        # Настройка мока
        mock_client = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        mock_channel = MagicMock()

        mock_stdout.read.return_value = b"command output"
        mock_stderr.read.return_value = b""
        mock_stdout.channel = mock_channel
        mock_channel.recv_exit_status.return_value = 0

        mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

        # Создание соединения и выполнение команды
        conn = SSHConnection("192.168.1.1", 22, "root")
        conn.client = mock_client

        success, stdout, stderr = conn.execute("ls -la")

        # Проверки
        assert success is True
        assert stdout == "command output"
        assert stderr == ""
        mock_client.exec_command.assert_called_once_with("ls -la", timeout=10)

    def test_execute_command_with_exit_code(self):
        """Выполнение команды с ненулевым кодом выхода."""
        mock_client = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        mock_channel = MagicMock()

        mock_stdout.read.return_value = b""
        mock_stderr.read.return_value = b"error message"
        mock_stdout.channel = mock_channel
        mock_channel.recv_exit_status.return_value = 1  # Ошибка

        mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

        conn = SSHConnection("192.168.1.1", 22, "root")
        conn.client = mock_client

        success, stdout, stderr = conn.execute("false")

        assert success is False
        assert stderr == "error message"

    def test_execute_without_connection(self):
        """Попытка выполнить команду без установленного соединения."""
        conn = SSHConnection("192.168.1.1", 22, "root")

        with pytest.raises(RuntimeError, match="SSH соединение не установлено"):
            conn.execute("ls")

    def test_execute_command_exception(self):
        """Обработка исключения при выполнении команды."""
        mock_client = MagicMock()
        mock_client.exec_command.side_effect = Exception("Execution failed")

        conn = SSHConnection("192.168.1.1", 22, "root")
        conn.client = mock_client

        success, stdout, stderr = conn.execute("ls")

        assert success is False
        assert stdout == ""
        assert "Execution failed" in stderr


# ==================== ТЕСТЫ ЗАКРЫТИЯ СОЕДИНЕНИЯ ====================


class TestSSHConnectionClose:
    """Тесты закрытия SSH-соединения."""

    def test_close_connection(self):
        """Закрытие активного соединения."""
        mock_client = MagicMock()

        conn = SSHConnection("192.168.1.1", 22, "root")
        conn.client = mock_client

        conn.close()

        mock_client.close.assert_called_once()
        assert conn.client is None

    def test_close_already_closed(self):
        """Закрытие уже закрытого соединения."""
        conn = SSHConnection("192.168.1.1", 22, "root")
        conn.client = None

        # Не должно вызывать ошибок
        conn.close()

    def test_close_with_exception(self):
        """Обработка ошибки при закрытии соединения."""
        mock_client = MagicMock()
        mock_client.close.side_effect = Exception("Close error")

        conn = SSHConnection("192.168.1.1", 22, "root")
        conn.client = mock_client

        # Не должно выбрасывать исключение
        conn.close()
        assert conn.client is None


# ==================== ТЕСТЫ КОНТЕКСТНОГО МЕНЕДЖЕРА ====================


class TestSSHConnectionContextManager:
    """Тесты использования SSHConnection как контекстного менеджера."""

    @patch("app.services.ssh.connection.paramiko.SSHClient")
    def test_context_manager_success(self, mock_ssh_client_class):
        """Успешное использование контекстного менеджера."""
        mock_client = MagicMock()
        mock_ssh_client_class.return_value = mock_client

        with SSHConnection("192.168.1.1", 22, "root") as conn:
            conn.connect_with_password("password")
            assert conn.client is not None

        # После выхода из контекста соединение должно быть закрыто
        mock_client.close.assert_called_once()

    @patch("app.services.ssh.connection.paramiko.SSHClient")
    def test_context_manager_with_exception(self, mock_ssh_client_class):
        """Контекстный менеджер закрывает соединение даже при ошибке."""
        mock_client = MagicMock()
        mock_ssh_client_class.return_value = mock_client

        with pytest.raises(ValueError):
            with SSHConnection("192.168.1.1", 22, "root") as conn:
                conn.connect_with_password("password")
                raise ValueError("Test error")

        # Соединение должно быть закрыто даже после ошибки
        mock_client.close.assert_called_once()


# ==================== ТЕСТЫ ВСПОМОГАТЕЛЬНОЙ ФУНКЦИИ ====================


class TestSSHConnectionHelper:
    """Тесты вспомогательной функции ssh_connection()."""

    @patch("app.services.ssh.connection.paramiko.SSHClient")
    def test_ssh_connection_with_password(self, mock_ssh_client_class):
        """Использование ssh_connection() с паролем."""
        mock_client = MagicMock()
        mock_ssh_client_class.return_value = mock_client

        with ssh_connection("192.168.1.1", 22, "root", password="secret") as conn:
            assert isinstance(conn, SSHConnection)
            assert conn.host == "192.168.1.1"
            assert conn.port == 22
            assert conn.username == "root"

        mock_client.close.assert_called()

    @patch("app.services.ssh.connection.paramiko.SSHClient")
    @patch("app.services.ssh.connection.paramiko.RSAKey")
    def test_ssh_connection_with_key(self, mock_rsa_key, mock_ssh_client_class, rsa_private_key):
        """Использование ssh_connection() с приватным ключом."""
        mock_pkey = MagicMock()
        mock_rsa_key.from_private_key.return_value = mock_pkey

        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_client.get_transport.return_value = mock_transport
        mock_ssh_client_class.return_value = mock_client

        with ssh_connection("192.168.1.1", 22, "root", private_key=rsa_private_key) as conn:
            assert isinstance(conn, SSHConnection)

        mock_client.close.assert_called()

    def test_ssh_connection_without_credentials(self):
        """Ошибка при вызове ssh_connection() без пароля и ключа."""
        with pytest.raises(ValueError, match="Необходимо указать либо пароль, либо приватный ключ"):
            with ssh_connection("192.168.1.1", 22, "root"):
                pass

    @patch("app.services.ssh.connection.paramiko.SSHClient")
    def test_ssh_connection_connection_failure(self, mock_ssh_client_class):
        """Ошибка при неудачном подключении через ssh_connection()."""
        mock_client = MagicMock()
        mock_client.connect.side_effect = paramiko.AuthenticationException("Auth failed")
        mock_ssh_client_class.return_value = mock_client

        with pytest.raises(RuntimeError, match="Не удалось установить SSH соединение"):
            with ssh_connection("192.168.1.1", 22, "root", password="wrong") as _:
                pass
