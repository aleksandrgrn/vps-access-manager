"""
Key Service - обёртка над ssh_manager с полной обработкой ошибок

Все SSH операции с детальным логированием и обработкой ошибок.
ЯКОРЬ #1: БД обновляется ТОЛЬКО после успешной SSH операции!
"""

import logging
import os
from typing import Any, Dict, List

from cryptography.fernet import InvalidToken

from app.models import Server, SSHKey
from app.services.ssh import keys as ssh_keys
from app.services.ssh.connection import SSHConnection

logger = logging.getLogger(__name__)


def decrypt_access_key(access_key: "SSHKey") -> Dict[str, Any]:
    """
    Расшифровывает access key сервера с ПОЛНОЙ валидацией.

    Args:
        access_key: Объект SSHKey из БД

    Returns:
        Dict с ключами:
            - success (bool): Успех операции
            - private_key (str): Расшифрованный приватный ключ (если успех)
            - message (str): Сообщение об ошибке (если неудача)
            - error_type (str): Тип ошибки

    ЯКОРЬ: Эта функция КРИТИЧНА - без неё SSH операции невозможны!
    """
    logger.info(
        f"[DECRYPT_START] Начало расшифровки access_key "
        f"(key_id={access_key.id if access_key else None})"
    )

    # ЭТАП 1: Валидация входных данных
    if not access_key:
        logger.error("[DECRYPT_ERROR] access_key=None")
        return {
            "success": False,
            "message": "Ключ доступа для сервера не найден",
            "error_type": "missing_access_key",
        }

    # ЭТАП 2: Проверка ENCRYPTION_KEY
    encryption_key = os.environ.get("ENCRYPTION_KEY")
    if not encryption_key:
        logger.error("[DECRYPT_ERROR] ENCRYPTION_KEY не установлен в переменных окружения")
        return {
            "success": False,
            "message": "ENCRYPTION_KEY не установлен на сервере",
            "error_type": "missing_encryption_key",
        }

    # ЭТАП 3: Проверка зашифрованного ключа
    if not access_key.private_key_encrypted:
        logger.error(f"[DECRYPT_ERROR] private_key_encrypted пуст для ключа {access_key.id}")
        return {
            "success": False,
            "message": "Приватный ключ не найден в БД",
            "error_type": "missing_private_key",
        }

    # ЭТАП 4: Попытка расшифровки
    try:
        logger.debug(f"[DECRYPT_ATTEMPT] Расшифровка ключа {access_key.id}")
        private_key = ssh_keys.decrypt_private_key(access_key.private_key_encrypted, encryption_key)

        # ЭТАП 5: Валидация результата
        if not private_key or len(private_key) < 100:
            logger.error(
                f"[DECRYPT_ERROR_VALIDATION] Результат расшифровки пуст или слишком короткий "
                f"(len={len(private_key) if private_key else 0})"
            )
            return {
                "success": False,
                "message": "Расшифрованный ключ невалиден",
                "error_type": "invalid_decrypted_key",
            }

        logger.info(f"[DECRYPT_SUCCESS] Ключ {access_key.id} успешно расшифрован")
        return {"success": True, "private_key": private_key}

    except InvalidToken:
        logger.error(
            "[DECRYPT_ERROR_VALIDATION] InvalidToken - "
            "неверный ENCRYPTION_KEY или повреждённые данные"
        )
        return {
            "success": False,
            "message": "Неверный ключ шифрования или повреждённые данные",
            "error_type": "invalid_encryption_key",
        }

    except ValueError as ve:
        logger.error(f"[DECRYPT_ERROR_EXCEPTION] ValueError: {str(ve)}")
        return {
            "success": False,
            "message": f"Ошибка валидации при расшифровке: {str(ve)}",
            "error_type": "decryption_value_error",
        }

    except Exception as e:
        logger.error(f"[DECRYPT_ERROR_EXCEPTION] Неожиданная ошибка: {str(e)}")
        return {
            "success": False,
            "message": f"Критическая ошибка расшифровки: {str(e)}",
            "error_type": "decryption_critical_error",
        }


def revoke_key_from_single_server(
    server: Server, private_key: str, key_to_revoke: SSHKey
) -> Dict[str, Any]:
    """
    Отзывает SSH ключ с одного сервера.

    Args:
        server: Объект Server из БД
        private_key: Расшифрованный приватный ключ для доступа
        key_to_revoke: Ключ который нужно отозвать

    Returns:
        Dict с ключами:
            - success (bool): Успех операции
            - message (str): Сообщение
            - details (str): Детали ошибки (если неудача)
            - error_type (str): Тип ошибки

    ЯКОРЬ: Эта функция ДОЛЖНА вернуть success=False если SSH не удался!
    """
    logger.info(
        f"[REVOKE_SSH_START] Отзыв ключа {key_to_revoke.name} с сервера "
        f"{server.name} ({server.ip_address})"
    )

    try:
        # Валидация публичного ключа
        from app.services.ssh.keys import validate_ssh_public_key

        if not validate_ssh_public_key(key_to_revoke.public_key):
            logger.error("[REVOKE_INVALID_KEY] Невалидный публичный ключ")
            return {
                "success": False,
                "message": "Невалидный формат публичного ключа",
                "details": f"Сервер: {server.name}",
                "error_type": "invalid_key",
            }

        # Создаем SSH соединение
        conn = SSHConnection(server.ip_address, server.ssh_port, server.username)
        conn_success, conn_error = conn.connect_with_key(private_key, server)

        if not conn_success:
            logger.error(f"[REVOKE_CONNECTION_FAILED] {conn_error}")
            return {
                "success": False,
                "message": conn_error or "Не удалось подключиться к серверу",
                "details": f"Сервер: {server.name} ({server.ip_address}:{server.ssh_port})",
                "error_type": "connection_failed",
            }

        try:
            # Шаг 1: Создаем backup
            logger.info(f"[REVOKE_BACKUP] Создание backup authorized_keys на {server.name}")
            backup_success, _, backup_stderr = conn.execute(
                "cp ~/.ssh/authorized_keys ~/.ssh/authorized_keys.bak 2>/dev/null || true",
                timeout=10,
            )

            # Шаг 2: Читаем authorized_keys
            read_success, content, read_stderr = conn.execute(
                "cat ~/.ssh/authorized_keys 2>/dev/null || echo ''", timeout=10
            )
            if not read_success or not content:
                logger.info(f"[REVOKE_NO_FILE] authorized_keys не найден на {server.name}")
                conn.close()
                return {
                    "success": True,
                    "message": "authorized_keys не найден (ключ отсутствует)",
                    "error_type": "SUCCESS",
                }

            # Шаг 3: Удаляем строку с ключом
            lines = content.strip().split("\n")
            key_to_revoke_stripped = key_to_revoke.public_key.strip()
            original_line_count = len(lines)

            new_lines = [
                line for line in lines if line.strip() and key_to_revoke_stripped not in line
            ]

            if len(new_lines) == original_line_count:
                logger.warning(
                    f"[REVOKE_KEY_NOT_FOUND] Ключ не найден в authorized_keys на {server.name}"
                )
                conn.close()
                return {
                    "success": False,
                    "message": "Ключ не найден в authorized_keys",
                    "details": f"Сервер: {server.name}",
                    "error_type": "KEY_NOT_FOUND",
                }

            # Шаг 4: Записываем новый authorized_keys
            new_content = "\n".join(new_lines)
            if new_content and not new_content.endswith("\n"):
                new_content += "\n"

            escaped_content = new_content.replace("'", "'\\''")
            write_success, _, write_stderr = conn.execute(
                f"echo -n '{escaped_content}' > ~/.ssh/authorized_keys && "
                f"chmod 600 ~/.ssh/authorized_keys",
                timeout=15,
            )

            if write_success:
                logger.info(f"[REVOKE_SUCCESS] Ключ успешно удалён с {server.name}")
                success = True
                message = f"Ключ успешно отозван с сервера {server.name}"
                error_type = None
            else:
                logger.error(f"[REVOKE_WRITE_FAILED] {write_stderr}")
                # Пытаемся восстановить backup
                conn.execute(
                    "mv ~/.ssh/authorized_keys.bak ~/.ssh/authorized_keys 2>/dev/null || true",
                    timeout=10,
                )
                success = False
                message = f"Ошибка при записи authorized_keys: {write_stderr}"
                error_type = "ssh_revoke_failed"
        finally:
            conn.close()

        if success:
            logger.info(f"[REVOKE_SSH_SUCCESS] Ключ успешно удалён с {server.name}")
            return {"success": True, "message": f"Ключ успешно отозван с сервера {server.name}"}
        else:
            logger.warning(
                f"[REVOKE_SSH_FAILED] Не удалось удалить ключ: {message} (error_type={error_type})"
            )
            return {
                "success": False,
                "message": message,
                "details": f"Сервер: {server.name} ({server.ip_address}:{server.ssh_port})",
                "error_type": error_type or "ssh_revoke_failed",
            }

    except Exception as e:
        logger.error(f"[REVOKE_SSH_EXCEPTION] Исключение при отзыве: {str(e)}")
        return {
            "success": False,
            "message": f"SSH ошибка: {str(e)}",
            "details": f"Не удалось подключиться к {server.ip_address}:{server.ssh_port}",
            "error_type": "ssh_exception",
        }


def revoke_key_from_all_servers(
    key: SSHKey, servers: List[Server], access_keys: Dict[int, SSHKey]
) -> Dict[str, Any]:
    """
    Отзывает ключ со всех серверов (bulk operation).

    Args:
        key: Ключ для отзыва
        servers: Список серверов
        access_keys: Словарь {server_id: access_key}

    Returns:
        Dict с ключами:
            - success_count (int): Количество успешных отзывов
            - failed_count (int): Количество неудачных
            - results (List[Dict]): Детали по каждому серверу
    """
    logger.info(f"[REVOKE_BULK_START] Массовый отзыв ключа {key.name} с {len(servers)} серверов")

    results = {"success_count": 0, "failed_count": 0, "results": []}

    for server in servers:
        access_key = access_keys.get(server.id)
        if not access_key:
            logger.warning(f"[REVOKE_BULK_SKIP] Нет access_key для сервера {server.name}")
            results["failed_count"] += 1
            results["results"].append(
                {
                    "server_name": server.name,
                    "server_ip": server.ip_address,
                    "success": False,
                    "message": "Нет ключа доступа для сервера",
                }
            )
            continue

        # Расшифровка
        decrypt_result = decrypt_access_key(access_key)
        if not decrypt_result["success"]:
            logger.warning(
                f"[REVOKE_BULK_DECRYPT_FAIL] Не удалось расшифровать ключ для {server.name}"
            )
            results["failed_count"] += 1
            results["results"].append(
                {
                    "server_name": server.name,
                    "server_ip": server.ip_address,
                    "success": False,
                    "message": decrypt_result["message"],
                }
            )
            continue

        # SSH отзыв
        revoke_result = revoke_key_from_single_server(server, decrypt_result["private_key"], key)

        if revoke_result["success"]:
            results["success_count"] += 1
        else:
            results["failed_count"] += 1

        results["results"].append(
            {
                "server_name": server.name,
                "server_ip": server.ip_address,
                "success": revoke_result["success"],
                "message": revoke_result["message"],
            }
        )

    logger.info(
        f"[REVOKE_BULK_COMPLETE] Успешно: {results['success_count']}, "
        f"Ошибок: {results['failed_count']}"
    )
    return results


def deploy_key_to_server(server: Server, private_key: str, key_to_deploy: SSHKey) -> Dict[str, Any]:
    """
    Развёртывает SSH ключ на сервере.

    Args:
        server: Объект Server
        private_key: Расшифрованный приватный ключ для доступа
        key_to_deploy: Ключ для развёртывания

    Returns:
        Dict с success, message, error_type
    """
    logger.info(f"[DEPLOY_START] Развёртывание ключа {key_to_deploy.name} на {server.name}")

    try:
        # Валидация публичного ключа
        from app.services.ssh.keys import validate_ssh_public_key

        if not validate_ssh_public_key(key_to_deploy.public_key):
            logger.error(f"[DEPLOY_FAILED] Невалидный публичный ключ: {key_to_deploy.name}")
            return {
                "success": False,
                "message": "Невалидный формат публичного ключа",
                "error_type": "invalid_key",
            }

        # Создаем SSH соединение
        conn = SSHConnection(server.ip_address, server.ssh_port, server.username)
        conn_success, conn_error = conn.connect_with_key(private_key, server)

        if not conn_success:
            logger.error(f"[DEPLOY_CONNECTION_FAILED] {conn_error}")
            return {
                "success": False,
                "message": conn_error or "Не удалось подключиться к серверу",
                "error_type": "connection_failed",
            }

        try:
            # Шаг 1: Создаем .ssh директорию
            cmd1_success, stdout1, stderr1 = conn.execute(
                "mkdir -p ~/.ssh && chmod 700 ~/.ssh", timeout=15
            )
            if not cmd1_success:
                logger.error(f"[DEPLOY_MKDIR_FAILED] {stderr1}")
                return {
                    "success": False,
                    "message": f"Не удалось создать .ssh: {stderr1}",
                    "error_type": "mkdir_failed",
                }

            # Шаг 2: Проверяем, не установлен ли уже ключ
            cmd2_success, existing_keys, stderr2 = conn.execute(
                "cat ~/.ssh/authorized_keys 2>/dev/null || echo ''", timeout=10
            )
            if key_to_deploy.public_key.strip() in existing_keys:
                logger.info(f"[DEPLOY_ALREADY_EXISTS] Ключ уже установлен на {server.name}")
                conn.close()
                return {"success": True, "message": f"Ключ уже установлен на {server.name}"}

            # Шаг 3: Добавляем ключ через echo и append
            escaped_key = key_to_deploy.public_key.strip().replace("'", "'\\''")
            cmd3_success, stdout3, stderr3 = conn.execute(
                f"echo '{escaped_key}' >> ~/.ssh/authorized_keys && "
                f"chmod 600 ~/.ssh/authorized_keys",
                timeout=15,
            )

            if cmd3_success:
                logger.info(f"[DEPLOY_SUCCESS] Ключ развёрнут на {server.name}")
                success = True
                message = f"Ключ успешно развёрнут на {server.name}"
            else:
                logger.error(f"[DEPLOY_APPEND_FAILED] {stderr3}")
                success = False
                message = f"Ошибка при добавлении ключа: {stderr3}"
        finally:
            conn.close()

        if success:
            logger.info(f"[DEPLOY_SUCCESS] Ключ развёрнут на {server.name}")
            return {"success": True, "message": f"Ключ успешно развёрнут на {server.name}"}
        else:
            logger.warning(f"[DEPLOY_FAILED] {message}")
            return {"success": False, "message": message, "error_type": "deploy_failed"}

    except Exception as e:
        logger.error(f"[DEPLOY_EXCEPTION] {str(e)}")
        return {
            "success": False,
            "message": f"Ошибка развёртывания: {str(e)}",
            "error_type": "deploy_exception",
        }


def test_server_connection(server: Server, private_key: str) -> Dict[str, Any]:
    """
    Тестирует SSH соединение с сервером с поддержкой legacy SSH.

    Args:
        server: Объект Server из БД
        private_key: Расшифрованный приватный ключ

    Returns:
        Dict с success, message, ssh_format
    """
    logger.info(f"[TEST_CONNECTION] Тестирование {server.name}")

    # Выбор формата ключа на основе флага из БД
    if server.requires_legacy_ssh:
        logger.info(f"[TEST_CONNECTION] Сервер {server.name} требует legacy SSH (OpenSSH < 7.2)")
        ssh_format = "legacy"
    else:
        logger.info(
            f"[TEST_CONNECTION] Сервер {server.name} использует modern SSH (OpenSSH >= 7.2)"
        )
        ssh_format = "modern"

    try:
        # Создаем SSH соединение с поддержкой legacy SSH
        conn = SSHConnection(server.ip_address, server.ssh_port, server.username)
        success, error = conn.connect_with_key(private_key, server)

        if success:
            # Проверяем соединение командой echo
            try:
                cmd_success, stdout, stderr = conn.execute("echo 'Connection test'", timeout=10)
                if cmd_success:
                    message = f"SSH соединение успешно (формат: {ssh_format})"
                else:
                    success = False
                    message = f"Соединение установлено, но команда не выполнена: {stderr}"
            except Exception as e:
                success = False
                message = f"Ошибка выполнения тестовой команды: {str(e)}"
            finally:
                conn.close()
        else:
            message = error or "Неизвестная ошибка подключения"

        if success:
            logger.info(
                f"[TEST_CONNECTION_SUCCESS] Соединение с {server.name} успешно "
                f"установлено ({ssh_format})"
            )
            return {
                "success": True,
                "message": f"SSH соединение успешно (формат: {ssh_format})",
                "ssh_format": ssh_format,
            }
        else:
            logger.warning(f"[TEST_CONNECTION_FAILED] Ошибка соединения с {server.name}: {message}")
            return {"success": False, "message": message, "ssh_format": ssh_format}

    except Exception as e:
        logger.error(
            f"[TEST_CONNECTION_EXCEPTION] Исключение при тестировании {server.name}: {str(e)}"
        )
        return {
            "success": False,
            "message": f"Ошибка тестирования: {str(e)}",
            "ssh_format": ssh_format,
        }
