"""
SSH Connection Module - управление SSH соединениями.

Этот модуль предоставляет класс SSHConnection для управления SSH соединениями
с поддержкой подключения по паролю и по ключу.
"""

import io
import logging
from contextlib import contextmanager
from typing import Optional, Tuple

import paramiko

# Настройка логирования
logger = logging.getLogger(__name__)


class CustomHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """
    Политика для обработки ключей хостов с сохранением в локальный файл.
    Предотвращает MitM-атаки, запоминая ключи известных хостов.
    """

    KNOWN_HOSTS_FILE = "known_hosts.json"

    def __init__(self):
        import base64
        import json
        import os

        self.json = json
        self.os = os
        self.base64 = base64
        self.known_hosts = self._load_known_hosts()

    def _load_known_hosts(self):
        """Загружает известные хосты из файла."""
        if self.os.path.exists(self.KNOWN_HOSTS_FILE):
            try:
                with open(self.KNOWN_HOSTS_FILE, "r") as f:
                    return self.json.load(f)
            except (self.json.JSONDecodeError, IOError) as e:
                logger.warning(f"Ошибка при загрузке known_hosts: {e}")
                return {}
        return {}

    def _save_known_hosts(self):
        """Сохраняет известные хосты в файл."""
        try:
            with open(self.KNOWN_HOSTS_FILE, "w") as f:
                self.json.dump(self.known_hosts, f, indent=4)
        except IOError as e:
            logger.error(f"Ошибка при сохранении known_hosts: {e}")

    def missing_host_key(self, client, hostname: str, key):
        """
        Обработчик для новых ключей хостов.

        Args:
            client: SSH клиент.
            hostname: Имя хоста.
            key: Ключ хоста.

        Raises:
            paramiko.SSHException: Если ключ хоста изменился.
        """
        key_type = key.get_name()
        key_str = self.base64.b64encode(key.asbytes()).decode("utf-8")

        port = client.get_transport().getpeername()[1]
        host_entry = f"[{hostname}]:{port}"

        fingerprint = ":".join(f"{b:02x}" for b in key.get_fingerprint())

        if host_entry in self.known_hosts:
            known_key_type = self.known_hosts[host_entry]["key_type"]
            known_key_str = self.known_hosts[host_entry]["key"]

            if known_key_type == key_type and known_key_str == key_str:
                logger.debug(f"Ключ хоста {host_entry} совпадает с известным")
                return
            else:
                logger.error(f"ПРЕДУПРЕЖДЕНИЕ: Ключ хоста изменился для {host_entry}!")
                raise paramiko.SSHException(
                    f"!!! ПРЕДУПРЕЖДЕНИЕ: КЛЮЧ ХОСТА ИЗМЕНИЛСЯ ДЛЯ {host_entry}! "
                    f"ВОЗМОЖНА АТАКА 'MAN-IN-THE-MIDDLE'!"
                )
        else:
            logger.info(f"Добавление нового хоста {host_entry} с fingerprint {fingerprint}")
            self.known_hosts[host_entry] = {"key_type": key_type, "key": key_str}
            self._save_known_hosts()


class SSHConnection:
    """
    Класс для управления SSH соединениями.

    Поддерживает подключение по паролю и по ключу,
    а также может использоваться как контекстный менеджер.
    """

    def __init__(self, host: str, port: int, username: str):
        """
        Инициализация SSH соединения.

        Args:
            host: Адрес хоста.
            port: Порт SSH.
            username: Имя пользователя.
        """
        self.host = host
        self.port = port
        self.username = username
        self.client: Optional[paramiko.SSHClient] = None

    def connect_with_password(self, password: str) -> Tuple[bool, Optional[str]]:
        """
        Подключается к серверу с использованием пароля.

        Args:
            password: Пароль.

        Returns:
            Tuple[bool, Optional[str]]: (успех, ошибка).
        """
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(CustomHostKeyPolicy())
            self.client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=password,
                timeout=15,
                allow_agent=False,
                look_for_keys=False,
            )
            logger.info(f"Подключение с паролем к {self.host}:{self.port} успешно")
            return True, None
        except paramiko.AuthenticationException:
            logger.error(f"Ошибка аутентификации на {self.host}:{self.port}")
            return False, "Ошибка аутентификации: неверный пароль или имя пользователя."
        except paramiko.SSHException as e:
            logger.error(f"Ошибка SSH на {self.host}:{self.port}: {str(e)}")
            return False, f"Ошибка SSH: {str(e)}"
        except Exception as e:
            logger.error(f"Неизвестная ошибка при подключении к {self.host}:{self.port}: {str(e)}")
            return False, f"Неизвестная ошибка при подключении: {str(e)}"

    def connect_with_key(self, private_key_str: str, server_obj=None) -> Tuple[bool, Optional[str]]:
        """
        Подключается к серверу с использованием приватного ключа.
        Использует адаптивные алгоритмы в зависимости от версии OpenSSH на сервере.

        Args:
            private_key_str: Приватный ключ в формате строки.
            server_obj: Объект Server из БД (опционально, для адаптивных алгоритмов).

        Returns:
            Tuple[bool, Optional[str]]: (успех, ошибка).
        """
        key_file = None
        try:
            # Парсим приватный ключ
            key_file = io.StringIO(private_key_str)
            try:
                # Сначала пробуем загрузить как RSA (наиболее часто используемый)
                pkey = paramiko.RSAKey.from_private_key(key_file)
            except paramiko.SSHException:
                # Если не получилось, сбрасываем файл и пробуем Ed25519
                key_file.seek(0)
                try:
                    pkey = paramiko.Ed25519Key.from_private_key(key_file)
                except paramiko.SSHException:
                    raise paramiko.SSHException(
                        "Неподдерживаемый формат приватного ключа или неверный ключ"
                    )

            # Создаем SSH клиент
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(CustomHostKeyPolicy())

            # Базовые параметры подключения
            connect_kwargs = {
                "hostname": self.host,
                "port": self.port,
                "username": self.username,
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
                    f"🔧 Использование legacy SSH алгоритмов для {self.host}:{self.port} "
                    f"(OpenSSH версия: {getattr(server_obj, 'openssh_version', 'unknown')})"
                )
                connect_kwargs["disabled_algorithms"] = {
                    "pubkeys": ["rsa-sha2-512", "rsa-sha2-256"]
                }
            else:
                if server_obj:
                    logger.info(
                        f"✓ Использование стандартных SSH алгоритмов для {self.host}:{self.port} "
                        f"(OpenSSH версия: {getattr(server_obj, 'openssh_version', 'unknown')})"
                    )
                else:
                    logger.debug(
                        f"Использование стандартных SSH алгоритмов для {self.host}:{self.port} "
                        "(информация о сервере недоступна)"
                    )

            logger.debug(f"Подключение к {self.host}:{self.port} как {self.username}")
            self.client.connect(**connect_kwargs)

            # Устанавливаем keepalive
            self.client.get_transport().set_keepalive(30)

            logger.info(f"SSH соединение успешно установлено с {self.host}:{self.port}")
            return True, None

        except paramiko.AuthenticationException as e:
            logger.error(f"Ошибка аутентификации на {self.host}:{self.port}: {str(e)}")
            return False, f"Ошибка аутентификации: {str(e)}"
        except paramiko.SSHException as e:
            logger.error(f"Ошибка SSH на {self.host}:{self.port}: {str(e)}")
            return False, f"Ошибка SSH: {str(e)}"
        except Exception as e:
            logger.error(f"Ошибка при подключении с ключом к {self.host}:{self.port}: {str(e)}")
            return False, f"Ошибка при подключении: {str(e)}"
        finally:
            if key_file:
                key_file.close()

    def execute(self, command: str, timeout: int = 10) -> Tuple[bool, str, str]:
        """
        Выполняет команду через SSH.

        Args:
            command: Команда для выполнения.
            timeout: Таймаут выполнения команды в секундах.

        Returns:
            Tuple[bool, str, str]: (успех, stdout, stderr).

        Raises:
            RuntimeError: Если соединение не установлено.
        """
        if not self.client:
            raise RuntimeError("SSH соединение не установлено. Сначала вызовите connect_*")

        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)  # nosec
            stdout_str = stdout.read().decode("utf-8")
            stderr_str = stderr.read().decode("utf-8")
            exit_status = stdout.channel.recv_exit_status()

            success = exit_status == 0
            logger.debug(
                f"Команда '{command}' выполнена на {self.host}:{self.port} "
                f"с кодом {exit_status}"
            )

            return success, stdout_str, stderr_str

        except Exception as e:
            logger.error(f"Ошибка при выполнении команды '{command}': {str(e)}")
            return False, "", str(e)

    def close(self):
        """Закрывает SSH соединение."""
        if self.client:
            try:
                self.client.close()
                logger.info(f"SSH соединение с {self.host}:{self.port} закрыто")
            except Exception as e:
                logger.warning(f"Ошибка при закрытии SSH соединения: {e}")
            finally:
                self.client = None

    def __enter__(self):
        """Вход в контекстный менеджер."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Выход из контекстного менеджера."""
        self.close()


@contextmanager
def ssh_connection(
    host: str,
    port: int,
    username: str,
    password: str = None,
    private_key: str = None,
    server_obj=None,
):
    """
    Контекстный менеджер для SSH соединения.

    Args:
        host: Адрес хоста.
        port: Порт SSH.
        username: Имя пользователя.
        password: Пароль (опционально).
        private_key: Приватный ключ (опционально).
        server_obj: Объект Server из БД (опционально).

    Yields:
        SSHConnection: Объект соединения.

    Raises:
        ValueError: Если не указан ни пароль, ни приватный ключ.
        RuntimeError: Если не удалось установить соединение.

    Example:
        with ssh_connection('192.168.1.1', 22, 'root', password='secret') as conn:
            success, stdout, stderr = conn.execute('ls -la')
    """
    if not password and not private_key:
        raise ValueError("Необходимо указать либо пароль, либо приватный ключ")

    conn = SSHConnection(host, port, username)
    try:
        # Подключаемся
        if password:
            success, error = conn.connect_with_password(password)
        else:
            success, error = conn.connect_with_key(private_key, server_obj)

        if not success:
            raise RuntimeError(f"Не удалось установить SSH соединение: {error}")

        yield conn

    finally:
        conn.close()
