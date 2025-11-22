"""
SSH Connection Module

Handles SSH connection establishment, host key verification, and connection testing.
"""

import base64
import io
import json
import logging
import os
from typing import Dict, Optional, Tuple

import paramiko

logger = logging.getLogger(__name__)


class CustomHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """
    Кастомная политика проверки хост-ключей.
    Сохраняет новые ключи в known_hosts.json и предупреждает о подмене.
    """

    KNOWN_HOSTS_FILE = "known_hosts.json"

    def __init__(self):
        self.known_hosts = self._load_known_hosts()

    def _load_known_hosts(self) -> Dict:
        if os.path.exists(self.KNOWN_HOSTS_FILE):
            try:
                with open(self.KNOWN_HOSTS_FILE, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Ошибка загрузки known_hosts: {e}")
                return {}
        return {}

    def _save_known_hosts(self) -> None:
        try:
            with open(self.KNOWN_HOSTS_FILE, "w") as f:
                json.dump(self.known_hosts, f, indent=4)
        except Exception as e:
            logger.error(f"Ошибка сохранения known_hosts: {e}")

    def missing_host_key(self, client, hostname: str, key) -> None:
        key_type = key.get_name()
        key_str = base64.b64encode(key.asbytes()).decode("utf-8")

        # Получаем порт и формируем запись вида [ip]:port
        # Paramiko не передает порт в missing_host_key, поэтому пытаемся достать из транспорта
        port = client.get_transport().getpeername()[1]
        host_entry = f"[{hostname}]:{port}"

        fingerprint = ":".join(f"{b:02x}" for b in key.get_fingerprint())

        if host_entry in self.known_hosts:
            saved_key = self.known_hosts[host_entry]
            if saved_key["key"] != key_str:
                msg = (
                    f"⚠️ ВНИМАНИЕ! Ключ хоста {host_entry} ИЗМЕНИЛСЯ! "
                    f"Возможна атака Man-in-the-Middle! "
                    f"Старый: {saved_key['key'][:20]}..., Новый: {key_str[:20]}..."
                )
                logger.critical(msg)
                raise paramiko.SSHException(f"Host key for {host_entry} has changed!")
            else:
                # Ключ совпадает, все ок
                pass
        else:
            logger.info(f"Добавление нового хоста {host_entry} с fingerprint {fingerprint}")
            self.known_hosts[host_entry] = {"key_type": key_type, "key": key_str}
            self._save_known_hosts()


def _get_ssh_client(ip: str, port: int, username: str, private_key_str: str) -> paramiko.SSHClient:
    """
    Создает и возвращает настроенный SSH клиент.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(CustomHostKeyPolicy())

    key_file = None
    try:
        key_file = io.StringIO(private_key_str)
        if "RSA" in private_key_str:
            private_key = paramiko.RSAKey.from_private_key(key_file)
        elif "PRIVATE KEY" in private_key_str:
            private_key = paramiko.Ed25519Key.from_private_key(key_file)
        else:
            raise paramiko.SSHException("Неподдерживаемый формат приватного ключа")

        connect_kwargs = {
            "hostname": ip,
            "port": port,
            "username": username,
            "pkey": private_key,
            "timeout": 15,
            "banner_timeout": 30,
            "auth_timeout": 20,
            "allow_agent": False,
            "look_for_keys": False,
        }

        client.connect(**connect_kwargs)
        client.get_transport().set_keepalive(30)

        logger.info(f"SSH соединение успешно установлено с {ip}:{port}")
        return client

    except Exception as e:
        logger.error(f"Ошибка создания SSH клиента для {ip}:{port}: {str(e)}")
        if client:
            client.close()
        if key_file:
            key_file.close()
        raise


def connect_with_adaptive_algorithms(
    ip: str, port: int, username: str, pkey, server_obj
) -> Optional[paramiko.SSHClient]:
    """
    Подключается к серверу с адаптивными алгоритмами в зависимости от версии OpenSSH.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(CustomHostKeyPolicy())

    try:
        # Базовые параметры подключения
        connect_kwargs = {
            "hostname": ip,
            "port": port,
            "username": username,
            "pkey": pkey,
            "timeout": 15,
            "banner_timeout": 30,
            "auth_timeout": 20,
            "allow_agent": False,
            "look_for_keys": False,
        }

        # Если требуется legacy SSH, отключаем новые алгоритмы
        if (
            server_obj
            and hasattr(server_obj, "requires_legacy_ssh")
            and server_obj.requires_legacy_ssh
        ):
            logger.info(
                f"Using legacy SSH algorithms for {ip}:{port} "
                f"(OpenSSH version: {getattr(server_obj, 'openssh_version', 'unknown')})"
            )
            connect_kwargs["disabled_algorithms"] = {"pubkeys": ["rsa-sha2-512", "rsa-sha2-256"]}
        else:
            if server_obj:
                logger.info(
                    f"✓ Использование стандартных SSH алгоритмов для {ip}:{port} "
                    f"(OpenSSH версия: {getattr(server_obj, 'openssh_version', 'unknown')})"
                )
            else:
                logger.debug(
                    f"Использование стандартных SSH алгоритмов для {ip}:{port} "
                    "(информация о сервере недоступна)"
                )

        logger.debug(f"Подключение к {ip}:{port} как {username} с параметрами: {connect_kwargs}")
        client.connect(**connect_kwargs)

        # Устанавливаем keepalive
        client.get_transport().set_keepalive(30)

        logger.info(f"SSH соединение успешно установлено с {ip}:{port}")
        return client

    except Exception as e:
        logger.error(f"Ошибка при подключении с адаптивными алгоритмами к {ip}:{port}: {str(e)}")
        raise


def connect_with_password(
    ip: str, port: int, username: str, password: str
) -> Tuple[Optional[paramiko.SSHClient], Optional[str]]:
    """
    Подключение по паролю (для инициализации).
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(CustomHostKeyPolicy())

    try:
        client.connect(
            hostname=ip,
            port=port,
            username=username,
            password=password,
            timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )
        return client, None
    except Exception as e:
        return None, str(e)


def test_connection(ip: str, port: int, username: str, private_key_str: str) -> Tuple[bool, str]:
    """
    Проверяет возможность подключения к серверу.
    """
    client = None
    try:
        client = _get_ssh_client(ip, port, username, private_key_str)

        # Пробуем выполнить простую команду
        stdin, stdout, stderr = client.exec_command('echo "Connection test"', timeout=5)
        exit_status = stdout.channel.recv_exit_status()

        if exit_status == 0:
            return True, "Соединение успешно установлено"
        else:
            return False, f"Ошибка выполнения команды: {stderr.read().decode()}"

    except Exception as e:
        return False, f"Ошибка подключения: {str(e)}"
    finally:
        if client:
            client.close()


def parse_openssh_version(version_string: str) -> str:
    """
    Парсит версию OpenSSH из строки вывода ssh -V.
    """
    import re

    try:
        # Регулярное выражение для поиска версии OpenSSH
        match = re.search(r"OpenSSH[_\s]+(\d+\.\d+)", version_string)
        if match:
            version = match.group(1)
            logger.info(f"Распарсена версия OpenSSH: {version}")
            return version
        else:
            logger.warning(f"Не удалось распарсить версию из: {version_string}")
            return "unknown"
    except Exception as e:
        logger.error(f"Ошибка при парсинге версии OpenSSH: {e}")
        return "unknown"
