"""
Тесты для app/services/deployment_service.py

Покрывают бизнес-логику деплоя и отзыва ключей.
"""

from datetime import datetime, timezone
from unittest.mock import Mock, patch

import pytest

from app.services.deployment_service import (
    deploy_key_to_servers,
    revoke_deployment_by_id,
    revoke_key_from_server_by_ids,
    revoke_key_globally,
)


@pytest.fixture
def mock_user():
    """Создает мок пользователя."""
    user = Mock()
    user.id = 1
    return user


@pytest.fixture
def mock_key():
    """Создает мок SSH-ключа."""
    key = Mock()
    key.id = 10
    key.name = "test-key"
    key.user_id = 1
    key.public_key = "ssh-rsa AAAAB3..."
    return key


@pytest.fixture
def mock_server():
    """Создает мок сервера."""
    server = Mock()
    server.id = 100
    server.name = "test-server"
    server.ip_address = "192.168.1.100"
    server.user_id = 1
    server.access_key = "encrypted_access_key_data"
    return server


@pytest.fixture
def mock_deployment():
    """Создает мок деплоймента."""
    deployment = Mock()
    deployment.id = 1000
    deployment.ssh_key_id = 10
    deployment.server_id = 100
    deployment.deployed_by = 1
    deployment.deployed_at = datetime.now(timezone.utc)
    deployment.revoked_at = None
    deployment.revoked_by = None
    return deployment


class TestDeployKeyToServers:
    """Тесты для функции deploy_key_to_servers."""

    @patch("app.services.deployment_service.add_log")
    @patch("app.services.deployment_service.db.session")
    @patch("app.services.deployment_service.deploy_key_to_server")
    @patch("app.services.deployment_service.decrypt_access_key")
    @patch("app.services.deployment_service.KeyDeployment")
    @patch("app.services.deployment_service.Server")
    @patch("app.services.deployment_service.SSHKey")
    def test_deploy_key_success(
        self,
        mock_ssh_key_class,
        mock_server_class,
        mock_deployment_class,
        mock_decrypt,
        mock_deploy,
        mock_db_session,
        mock_add_log,
        mock_key,
        mock_server,
    ):
        """
        Тест успешного деплоя ключа.
        Проверяет, что вызывается SSH deploy и создается KeyDeployment.
        """
        # Настраиваем моки
        mock_ssh_key_class.query.get.return_value = mock_key
        mock_server_class.query.get.return_value = mock_server

        # Мокаем отсутствие существующего деплоймента
        mock_deployment_class.query.filter_by.return_value.first.return_value = None

        # Мокаем успешную расшифровку
        mock_decrypt.return_value = {
            "success": True,
            "private_key": "decrypted_private_key",
        }

        # Мокаем успешный деплой через SSH
        mock_deploy.return_value = {
            "success": True,
            "message": "Successfully deployed",
        }

        # Выполняем деплой
        result = deploy_key_to_servers(
            user_id=1,
            key_id=10,
            server_ids=[100],
        )

        # Проверяем результат
        assert result["success"] is True
        assert result["success_count"] == 1
        assert result["failed_count"] == 0
        assert len(result["results"]) == 1
        assert result["results"][0]["success"] is True

        # Проверяем, что decrypt_access_key был вызван
        mock_decrypt.assert_called_once_with("encrypted_access_key_data")

        # Проверяем, что deploy_key_to_server был вызван
        mock_deploy.assert_called_once_with(
            mock_server,
            "decrypted_private_key",
            mock_key,
        )

        # Проверяем, что KeyDeployment был создан и добавлен в сессию
        mock_deployment_class.assert_called_once()
        mock_db_session.add.assert_called_once()
        mock_db_session.commit.assert_called()

        # Проверяем логирование
        mock_add_log.assert_called_once()

    @patch("app.services.deployment_service.add_log")
    @patch("app.services.deployment_service.db.session")
    @patch("app.services.deployment_service.deploy_key_to_server")
    @patch("app.services.deployment_service.decrypt_access_key")
    @patch("app.services.deployment_service.KeyDeployment")
    @patch("app.services.deployment_service.Server")
    @patch("app.services.deployment_service.SSHKey")
    def test_deploy_key_ssh_fail(
        self,
        mock_ssh_key_class,
        mock_server_class,
        mock_deployment_class,
        mock_decrypt,
        mock_deploy,
        mock_db_session,
        mock_add_log,
        mock_key,
        mock_server,
    ):
        """
        Тест неудачного SSH деплоя.
        Проверяет, что если SSH вернул False, то KeyDeployment НЕ создается.
        """
        # Настраиваем моки
        mock_ssh_key_class.query.get.return_value = mock_key
        mock_server_class.query.get.return_value = mock_server
        mock_deployment_class.query.filter_by.return_value.first.return_value = None

        # Мокаем успешную расшифровку
        mock_decrypt.return_value = {
            "success": True,
            "private_key": "decrypted_private_key",
        }

        # Мокаем НЕУДАЧНЫЙ деплой через SSH
        mock_deploy.return_value = {
            "success": False,
            "message": "SSH connection failed",
            "error_type": "ssh_error",
        }

        # Выполняем деплой
        result = deploy_key_to_servers(
            user_id=1,
            key_id=10,
            server_ids=[100],
        )

        # Проверяем результат
        assert result["success"] is True  # Общий результат успешен (операция выполнена)
        assert result["success_count"] == 0  # Но ни один сервер не был успешно обработан
        assert result["failed_count"] == 1
        assert len(result["results"]) == 1
        assert result["results"][0]["success"] is False
        assert "SSH connection failed" in result["results"][0]["error"]

        # Проверяем, что deploy_key_to_server был вызван
        mock_deploy.assert_called_once()

        # Проверяем, что KeyDeployment НЕ был создан
        mock_deployment_class.assert_not_called()
        mock_db_session.add.assert_not_called()

    @patch("app.services.deployment_service.SSHKey")
    def test_deploy_key_missing_parameters(self, mock_ssh_key_class):
        """Тест на отсутствие обязательных параметров."""
        result = deploy_key_to_servers(
            user_id=1,
            key_id=None,  # Отсутствует key_id
            server_ids=[100],
        )

        assert result["success"] is False
        assert result["error_type"] == "missing_parameters"

    @patch("app.services.deployment_service.SSHKey")
    def test_deploy_key_not_found(self, mock_ssh_key_class):
        """Тест на несуществующий ключ."""
        mock_ssh_key_class.query.get.return_value = None

        result = deploy_key_to_servers(
            user_id=1,
            key_id=999,  # Несуществующий ключ
            server_ids=[100],
        )

        assert result["success"] is False
        assert result["error_type"] == "key_not_found"

    @patch("app.services.deployment_service.SSHKey")
    def test_deploy_key_access_denied(self, mock_ssh_key_class, mock_key):
        """Тест на отказ в доступе к ключу."""
        mock_key.user_id = 999  # Другой пользователь
        mock_ssh_key_class.query.get.return_value = mock_key

        result = deploy_key_to_servers(
            user_id=1,
            key_id=10,
            server_ids=[100],
        )

        assert result["success"] is False
        assert result["error_type"] == "access_denied"


class TestRevokeDeploymentById:
    """Тесты для функции revoke_deployment_by_id."""

    @patch("app.services.deployment_service.add_log")
    @patch("app.services.deployment_service.db.session")
    @patch("app.services.deployment_service.revoke_key_from_single_server")
    @patch("app.services.deployment_service.decrypt_access_key")
    @patch("app.services.deployment_service.KeyDeployment")
    def test_revoke_deployment_success(
        self,
        mock_deployment_class,
        mock_decrypt,
        mock_revoke,
        mock_db_session,
        mock_add_log,
        mock_deployment,
        mock_key,
        mock_server,
    ):
        """
        Тест успешного отзыва деплоймента.
        Проверяет, что вызывается SSH revoke и обновляется revoked_at.
        """
        # Настраиваем моки
        mock_deployment.ssh_key = mock_key
        mock_deployment.server = mock_server
        mock_deployment_class.query.get.return_value = mock_deployment

        # Мокаем успешную расшифровку
        mock_decrypt.return_value = {
            "success": True,
            "private_key": "decrypted_private_key",
        }

        # Мокаем успешный отзыв через SSH
        mock_revoke.return_value = {
            "success": True,
            "message": "Key successfully revoked",
        }

        # Выполняем отзыв
        result = revoke_deployment_by_id(user_id=1, deployment_id=1000)

        # Проверяем результат
        assert result["success"] is True
        assert result["server"] == "test-server"
        assert result["ip"] == "192.168.1.100"

        # Проверяем, что decrypt_access_key был вызван
        mock_decrypt.assert_called_once_with("encrypted_access_key_data")

        # Проверяем, что revoke_key_from_single_server был вызван
        mock_revoke.assert_called_once_with(
            mock_server,
            "decrypted_private_key",
            mock_key,
        )

        # Проверяем, что revoked_at был установлен
        assert mock_deployment.revoked_at is not None
        assert mock_deployment.revoked_by == 1

        # Проверяем, что изменения были сохранены
        mock_db_session.commit.assert_called_once()

        # Проверяем логирование
        mock_add_log.assert_called_once()

    @patch("app.services.deployment_service.KeyDeployment")
    def test_revoke_deployment_not_found(self, mock_deployment_class):
        """Тест на несуществующий деплоймент."""
        mock_deployment_class.query.get.return_value = None

        result = revoke_deployment_by_id(user_id=1, deployment_id=9999)

        assert result["success"] is False
        assert result["error_type"] == "not_found"

    @patch("app.services.deployment_service.KeyDeployment")
    def test_revoke_deployment_already_revoked(self, mock_deployment_class, mock_deployment):
        """Тест на уже отозванный деплоймент."""
        mock_deployment.revoked_at = datetime.now(timezone.utc)
        mock_deployment_class.query.get.return_value = mock_deployment

        result = revoke_deployment_by_id(user_id=1, deployment_id=1000)

        assert result["success"] is False
        assert result["error_type"] == "already_revoked"

    @patch("app.services.deployment_service.add_log")
    @patch("app.services.deployment_service.revoke_key_from_single_server")
    @patch("app.services.deployment_service.decrypt_access_key")
    @patch("app.services.deployment_service.KeyDeployment")
    def test_revoke_deployment_ssh_fail(
        self,
        mock_deployment_class,
        mock_decrypt,
        mock_revoke,
        mock_add_log,
        mock_deployment,
        mock_key,
        mock_server,
    ):
        """Тест на неудачный SSH отзыв."""
        # Настраиваем моки
        mock_deployment.ssh_key = mock_key
        mock_deployment.server = mock_server
        mock_deployment_class.query.get.return_value = mock_deployment

        mock_decrypt.return_value = {
            "success": True,
            "private_key": "decrypted_private_key",
        }

        # Мокаем НЕУДАЧНЫЙ отзыв через SSH
        mock_revoke.return_value = {
            "success": False,
            "message": "SSH error occurred",
            "error_type": "ssh_error",
        }

        result = revoke_deployment_by_id(user_id=1, deployment_id=1000)

        assert result["success"] is False
        assert result["error_type"] == "ssh_error"
        assert "Failed to revoke key" in result["message"]


class TestRevokeKeyFromServerByIds:
    """Тесты для функции revoke_key_from_server_by_ids."""

    @patch("app.services.deployment_service.revoke_deployment_by_id")
    @patch("app.services.deployment_service.KeyDeployment")
    @patch("app.services.deployment_service.Server")
    @patch("app.services.deployment_service.SSHKey")
    def test_revoke_key_from_server_by_ids_success(
        self,
        mock_ssh_key_class,
        mock_server_class,
        mock_deployment_class,
        mock_revoke_by_id,
        mock_key,
        mock_server,
        mock_deployment,
    ):
        """Тест успешного отзыва по ID ключа и сервера."""
        mock_ssh_key_class.query.get.return_value = mock_key
        mock_server_class.query.get.return_value = mock_server
        mock_deployment_class.query.filter_by.return_value.first.return_value = mock_deployment

        mock_revoke_by_id.return_value = {
            "success": True,
            "message": "Key revoked",
        }

        result = revoke_key_from_server_by_ids(
            user_id=1,
            key_id=10,
            server_id=100,
        )

        assert result["success"] is True
        mock_revoke_by_id.assert_called_once_with(1, mock_deployment.id)

    @patch("app.services.deployment_service.Server")
    @patch("app.services.deployment_service.SSHKey")
    def test_revoke_key_from_server_by_ids_not_found(self, mock_ssh_key_class, mock_server_class):
        """Тест на несуществующий ключ или сервер."""
        mock_ssh_key_class.query.get.return_value = None

        result = revoke_key_from_server_by_ids(
            user_id=1,
            key_id=999,
            server_id=100,
        )

        assert result["success"] is False
        assert result["error_type"] == "not_found"


class TestRevokeKeyGlobally:
    """Тесты для функции revoke_key_globally."""

    @patch("app.services.deployment_service.add_log")
    @patch("app.services.deployment_service.db.session")
    @patch("app.services.deployment_service.revoke_key_from_all_servers")
    @patch("app.services.deployment_service.Server")
    @patch("app.services.deployment_service.KeyDeployment")
    @patch("app.services.deployment_service.SSHKey")
    def test_revoke_globally_success(
        self,
        mock_ssh_key_class,
        mock_deployment_class,
        mock_server_class,
        mock_revoke_all,
        mock_db_session,
        mock_add_log,
        mock_key,
        mock_server,
        mock_deployment,
    ):
        """
        Тест глобального отзыва ключа.
        Проверяет вызов массового отзыва и обновление всех деплойментов.
        """
        # Настраиваем моки
        mock_ssh_key_class.query.get.return_value = mock_key

        # Создаем список активных деплойментов
        mock_deployment_class.query.filter_by.return_value.all.return_value = [mock_deployment]

        # Мокаем сервер
        mock_server_class.query.get.return_value = mock_server

        # Мокаем успешный массовый отзыв
        mock_revoke_all.return_value = {
            "success": True,
            "success_count": 1,
            "failed_count": 0,
            "results": [
                {
                    "success": True,
                    "server_name": "test-server",
                    "message": "Revoked successfully",
                }
            ],
        }

        # Мокаем поиск деплоймента для обновления
        mock_deployment_class.query.filter_by.return_value.first.return_value = mock_deployment

        # Выполняем глобальный отзыв
        result = revoke_key_globally(user_id=1, key_id=10)

        # Проверяем результат
        assert result["success"] is True
        assert result["completed"] == 1
        assert result["failed"] == 0

        # Проверяем, что revoke_key_from_all_servers был вызван
        mock_revoke_all.assert_called_once()

        # Проверяем, что revoked_at был установлен
        assert mock_deployment.revoked_at is not None
        assert mock_deployment.revoked_by == 1

        # Проверяем, что изменения были сохранены
        mock_db_session.commit.assert_called()

        # Проверяем логирование
        mock_add_log.assert_called_once()

    @patch("app.services.deployment_service.SSHKey")
    def test_revoke_globally_key_not_found(self, mock_ssh_key_class):
        """Тест на несуществующий ключ."""
        mock_ssh_key_class.query.get.return_value = None

        result = revoke_key_globally(user_id=1, key_id=999)

        assert result["success"] is False
        assert result["error_type"] == "not_found"

    @patch("app.services.deployment_service.KeyDeployment")
    @patch("app.services.deployment_service.SSHKey")
    def test_revoke_globally_no_deployments(
        self, mock_ssh_key_class, mock_deployment_class, mock_key
    ):
        """Тест на отсутствие активных деплойментов."""
        mock_ssh_key_class.query.get.return_value = mock_key
        mock_deployment_class.query.filter_by.return_value.all.return_value = []

        result = revoke_key_globally(user_id=1, key_id=10)

        assert result["success"] is True
        assert result["total"] == 0
        assert result["completed"] == 0
        assert "No active deployments" in result["message"]
