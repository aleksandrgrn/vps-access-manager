"""
Server Manager - управление подключением и инициализацией серверов.

Этот модуль предоставляет функции для:
- Инициализации сервера (проверка доступа, определение версии SSH)
- Тестирования соединения с использованием ключей
"""

import logging
import re
from typing import Any, Dict

from app.models import Server
from app.services.key_service import decrypt_access_key
from app.services.ssh.connection import SSHConnection

logger = logging.getLogger(__name__)


def parse_openssh_version(version_string: str) -> str:
    """
    Парсит версию OpenSSH из строки вывода ssh -V.

    Args:
        version_string: Строка вывода ssh -V (например "OpenSSH_5.3p1 OpenSSL 0.9.8e")

    Returns:
        str: Версия в формате "X.Y" (например "5.3") или "unknown"
    """
    try:
        # Регулярное выражение для поиска версии OpenSSH
        match = re.search(r"OpenSSH[_\s]+(\d+\.\d+)", version_string)
        if match:
            version = match.group(1)
            logger.debug(f"Распарсена версия OpenSSH: {version}")
            return version
        else:
            logger.warning(f"Не удалось распарсить версию из: {version_string}")
            return "unknown"
    except Exception as e:
        logger.error(f"Ошибка при парсинге версии OpenSSH: {e}")
        return "unknown"


def initialize_server(ip: str, port: int, username: str, password: str) -> Dict[str, Any]:
    """
    Инициализирует сервер: подключается по паролю и определяет версию OpenSSH.

    Args:
        ip: IP-адрес сервера.
        port: Порт SSH.
        username: Имя пользователя.
        password: Пароль.

    Returns:
        Dict: {
            'success': bool,
            'openssh_version': str (например "5.3" или "unknown"),
            'requires_legacy_ssh': bool (True если версия < 7.2),
            'message': str
        }
    """
    logger.info(f"Инициализация сервера {ip}:{port} (user={username})")

    conn = SSHConnection(ip, port, username)
    try:
        # 1. Подключение по паролю
        success, error = conn.connect_with_password(password)
        if not success:
            logger.error(f"Ошибка подключения к {ip}: {error}")
            return {
                "success": False,
                "openssh_version": "unknown",
                "requires_legacy_ssh": False,
                "message": error or "Ошибка подключения",
            }

        # 2. Определение версии OpenSSH
        # ssh -V пишет версию в stderr!
        cmd_success, stdout, stderr = conn.execute("ssh -V", timeout=10)

        # Объединяем stdout и stderr для поиска версии, так как ssh -V пишет в stderr
        version_output = (stdout + stderr).strip()
        openssh_version = parse_openssh_version(version_output)

        # 3. Определение необходимости legacy режима
        requires_legacy_ssh = False
        if openssh_version != "unknown":
            try:
                # Сравниваем версии как float (например 5.3 < 7.2)
                if float(openssh_version) < 7.2:
                    requires_legacy_ssh = True
                    logger.info(f"Сервер {ip} требует legacy SSH (версия {openssh_version})")
            except ValueError:
                logger.warning(f"Не удалось сравнить версию {openssh_version} как число")

        logger.info(
            f"Сервер {ip} инициализирован. Версия: {openssh_version}, Legacy: {requires_legacy_ssh}"
        )

        return {
            "success": True,
            "openssh_version": openssh_version,
            "requires_legacy_ssh": requires_legacy_ssh,
            "message": "Сервер успешно инициализирован",
        }

    except Exception as e:
        logger.error(f"Неожиданная ошибка при инициализации {ip}: {e}")
        return {
            "success": False,
            "openssh_version": "unknown",
            "requires_legacy_ssh": False,
            "message": f"Ошибка инициализации: {str(e)}",
        }
    finally:
        conn.close()


def test_connection(server: Server) -> Dict[str, Any]:
    """
    Тестирует SSH-соединение с сервером, используя сохраненный ключ.

    Args:
        server: Объект модели Server.

    Returns:
        Dict: {
            'success': bool,
            'message': str
        }
    """
    logger.info(f"Тестирование соединения с сервером {server.name} ({server.ip_address})")

    # 1. Получаем и расшифровываем ключ
    if not server.access_key:
        return {"success": False, "message": "Ключ доступа не привязан к серверу"}

    decrypted_data = decrypt_access_key(server.access_key)
    if not decrypted_data["success"]:
        return {
            "success": False,
            "message": f"Ошибка расшифровки ключа: {decrypted_data.get('message')}",
        }

    private_key = decrypted_data["private_key"]

    # 2. Подключаемся
    conn = SSHConnection(server.ip_address, server.ssh_port, server.username)
    try:
        success, error = conn.connect_with_key(private_key, server_obj=server)
        if not success:
            return {"success": False, "message": error or "Не удалось установить SSH соединение"}

        # 3. Проверяем выполнение команды
        cmd_success, stdout, stderr = conn.execute('echo "Connection test"', timeout=10)
        if not cmd_success:
            return {
                "success": False,
                "message": f"Соединение установлено, но команда не выполнена: {stderr}",
            }

        return {"success": True, "message": "Соединение успешно установлено и проверено"}

    except Exception as e:
        logger.error(f"Ошибка при тестировании соединения с {server.name}: {e}")
        return {"success": False, "message": f"Ошибка при тестировании: {str(e)}"}
    finally:
        conn.close()
