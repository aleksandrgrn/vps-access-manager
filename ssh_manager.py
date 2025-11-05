"""
SSH Manager - модуль для управления SSH ключами и операциями.

Этот модуль предоставляет функции для:
- Генерации SSH ключей (RSA, Ed25519)
- Шифрования/дешифрования приватных ключей
- Управления authorized_keys на удаленных серверах
- Развертывания и отзыва ключей
- Тестирования SSH соединений
"""

import io
import base64
import hashlib
import os
import json
import logging
import socket
import re
from typing import Tuple, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError

from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.fernet import Fernet
import paramiko

# Настройка логирования
logger = logging.getLogger(__name__)

def generate_ssh_key(key_type: str = "rsa") -> Tuple[str, str]:
    """
    Генерирует SSH-ключ типа RSA или Ed25519.
    
    Args:
        key_type: Тип ключа ('rsa' или 'ed25519'). По умолчанию 'rsa'.
        
    Returns:
        Tuple[str, str]: (приватный_ключ_PEM, публичный_ключ_OpenSSH)
        
    Raises:
        ValueError: Если указан неподдерживаемый тип ключа.
    """
    logger.info(f"Генерирование SSH ключа типа: {key_type}")
    
    try:
        if key_type == "rsa":
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
            )
        elif key_type == "ed25519":
            key = ed25519.Ed25519PrivateKey.generate()
        else:
            raise ValueError("Неподдерживаемый тип ключа. Используйте 'rsa' или 'ed25519'.")

        private_key_pem = key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.TraditionalOpenSSL,
            crypto_serialization.NoEncryption()
        )

        public_key_ssh = key.public_key().public_bytes(
            crypto_serialization.Encoding.OpenSSH,
            crypto_serialization.PublicFormat.OpenSSH
        )

        logger.info(f"SSH ключ успешно сгенерирован ({key_type})")
        return private_key_pem.decode('utf-8'), public_key_ssh.decode('utf-8')
        
    except Exception as e:
        logger.error(f"Ошибка при генерации SSH ключа: {e}")
        raise

def get_fingerprint(public_key_str: str) -> Optional[str]:
    """
    Вычисляет MD5 fingerprint для публичного ключа в формате SSH.
    
    Args:
        public_key_str: Публичный ключ в формате OpenSSH.
        
    Returns:
        Optional[str]: Fingerprint в формате 'xx:xx:xx:...' или None если ошибка.
    """
    try:
        key_parts = public_key_str.split()
        if len(key_parts) < 2:
            logger.warning("Некорректный формат публичного ключа")
            return None
            
        key_data = base64.b64decode(key_parts[1])
        md5_hash = hashlib.md5(key_data).hexdigest()
        fingerprint = ':'.join(a+b for a,b in zip(md5_hash[::2], md5_hash[1::2]))
        
        logger.debug(f"Вычислен fingerprint: {fingerprint}")
        return fingerprint
        
    except Exception as e:
        logger.error(f"Ошибка при вычислении fingerprint: {e}")
        return None

def validate_ssh_public_key(public_key: str) -> bool:
    """
    Валидирует формат SSH публичного ключа.
    
    Args:
        public_key: Публичный ключ для проверки.
        
    Returns:
        bool: True если ключ в корректном формате, False иначе.
    """
    try:
        parts = public_key.strip().split()
        if len(parts) < 2:
            return False
            
        # Проверяем что это SSH ключ
        if parts[0] not in ['ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521']:
            return False
            
        # Проверяем что base64 часть валидна
        try:
            base64.b64decode(parts[1])
            return True
        except Exception:
            return False
            
    except Exception as e:
        logger.warning(f"Ошибка при валидации публичного ключа: {e}")
        return False


def encrypt_private_key(private_key: str, encryption_key: str) -> bytes:
    """
    Шифрует приватный ключ с использованием Fernet.
    
    Args:
        private_key: Приватный ключ в формате PEM.
        encryption_key: Ключ шифрования (должен быть валидным Fernet ключом).
        
    Returns:
        bytes: Зашифрованный ключ.
        
    Raises:
        ValueError: Если encryption_key невалиден.
    """
    try:
        if not encryption_key:
            raise ValueError("Ключ шифрования не может быть пустым")
            
        f = Fernet(encryption_key.encode('utf-8'))
        encrypted_key = f.encrypt(private_key.encode('utf-8'))
        
        logger.info("Приватный ключ успешно зашифрован")
        return encrypted_key
        
    except Exception as e:
        logger.error(f"Ошибка при шифровании ключа: {e}")
        raise


def decrypt_private_key(encrypted_key: bytes, encryption_key: str) -> str:
    """
    Дешифрует приватный ключ.
    
    Args:
        encrypted_key: Зашифрованный ключ.
        encryption_key: Ключ шифрования.
        
    Returns:
        str: Дешифрованный приватный ключ в формате PEM.
        
    Raises:
        ValueError: Если дешифровка не удалась.
    """
    try:
        if not encryption_key:
            raise ValueError("Ключ шифрования не может быть пустым")
            
        f = Fernet(encryption_key.encode('utf-8'))
        decrypted_key = f.decrypt(encrypted_key)
        
        logger.debug("Приватный ключ успешно дешифрован")
        return decrypted_key.decode('utf-8')
        
    except Exception as e:
        logger.error(f"Ошибка при дешифровке ключа: {e}")
        raise

class CustomHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """
    Политика для обработки ключей хостов с сохранением в локальный файл.
    Предотвращает MitM-атаки, запоминая ключи известных хостов.
    """
    KNOWN_HOSTS_FILE = "known_hosts.json"
    
    def __init__(self):
        self.known_hosts = self._load_known_hosts()
    
    def _load_known_hosts(self) -> Dict:
        """Загружает известные хосты из файла."""
        if os.path.exists(self.KNOWN_HOSTS_FILE):
            try:
                with open(self.KNOWN_HOSTS_FILE, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Ошибка при загрузке known_hosts: {e}")
                return {}
        return {}
    
    def _save_known_hosts(self) -> None:
        """Сохраняет известные хосты в файл."""
        try:
            with open(self.KNOWN_HOSTS_FILE, 'w') as f:
                json.dump(self.known_hosts, f, indent=4)
        except IOError as e:
            logger.error(f"Ошибка при сохранении known_hosts: {e}")
    
    def missing_host_key(self, client, hostname: str, key) -> None:
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
        key_str = base64.b64encode(key.asbytes()).decode('utf-8')
        
        port = client.get_transport().getpeername()[1]
        host_entry = f"[{hostname}]:{port}"
        
        fingerprint = ':'.join(f'{b:02x}' for b in key.get_fingerprint())

        if host_entry in self.known_hosts:
            known_key_type = self.known_hosts[host_entry]['key_type']
            known_key_str = self.known_hosts[host_entry]['key']
            
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
            self.known_hosts[host_entry] = {
                'key_type': key_type,
                'key': key_str
            }
            self._save_known_hosts()

def _get_ssh_client(ip: str, port: int, username: str, private_key_str: str) -> paramiko.SSHClient:
    """
    Создает и настраивает SSH клиент Paramiko с улучшенной обработкой ошибок и таймаутами.
    
    Args:
        ip: IP-адрес сервера.
        port: Порт SSH.
        username: Имя пользователя для аутентификации.
        private_key_str: Приватный ключ в формате строки.
        
    Returns:
        paramiko.SSHClient: Настроенный SSH-клиент.
        
    Raises:
        paramiko.AuthenticationException: Если аутентификация не удалась.
        paramiko.SSHException: При ошибках SSH.
        socket.error: При проблемах с сетевым соединением.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(CustomHostKeyPolicy())
    
    key_file = None
    try:
        # Пробуем загрузить ключ
        key_file = io.StringIO(private_key_str)
        if 'RSA' in private_key_str:
            private_key = paramiko.RSAKey.from_private_key(key_file)
        elif 'PRIVATE KEY' in private_key_str:
            private_key = paramiko.Ed25519Key.from_private_key(key_file)
        else:
            raise paramiko.SSHException("Неподдерживаемый формат приватного ключа")
        
        # Параметры подключения
        connect_kwargs = {
            'hostname': ip,
            'port': port,
            'username': username,
            'pkey': private_key,
            'timeout': 15,           # Таймаут на установку соединения
            'banner_timeout': 30,    # Таймаут на баннер
            'auth_timeout': 20,      # Таймаут на аутентификацию
            'allow_agent': False,    # Отключаем использование SSH-агента
            'look_for_keys': False   # Не ищем ключи в стандартных путях
        }
        
        # Подключаемся к серверу
        logger.debug(f"Подключение к {ip}:{port} как {username}")
        client.connect(**connect_kwargs)
        
        # Устанавливаем keepalive для поддержания соединения
        client.get_transport().set_keepalive(30)
        
        logger.info(f"SSH соединение успешно установлено с {ip}:{port}")
        return client
        
    except paramiko.ssh_exception.SSHException as e:
        logger.error(f"Ошибка SSH при подключении к {ip}:{port}: {str(e)}")
        raise paramiko.SSHException(f"Ошибка SSH: {str(e)}")
    except socket.timeout as e:
        logger.error(f"Таймаут при подключении к {ip}:{port}")
        raise
    except Exception as e:
        logger.error(f"Не удалось установить SSH-соединение с {ip}:{port}: {str(e)}")
        raise Exception(f"Не удалось установить SSH-соединение: {str(e)}")
    finally:
        if key_file:
            key_file.close()

def test_connection(ip: str, port: int, username: str, private_key_str: str) -> Tuple[bool, str]:
    """
    Тестирует SSH-соединение с сервером с улучшенной обработкой ошибок.
    
    Args:
        ip: IP-адрес сервера.
        port: Порт SSH.
        username: Имя пользователя для аутентификации.
        private_key_str: Приватный ключ в формате строки.
        
    Returns:
        Tuple[bool, str]: (статус_подключения, сообщение).
    """
    client = None
    try:
        # Проверяем валидность IP-адреса
        try:
            socket.inet_pton(socket.AF_INET, ip)
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, ip)
            except socket.error:
                logger.warning(f"Некорректный IP-адрес: {ip}")
                return False, f"Некорректный IP-адрес: {ip}"
        
        # Проверяем порт
        if not (1 <= port <= 65535):
            logger.warning(f"Некорректный номер порта: {port}")
            return False, f"Некорректный номер порта: {port}"
        
        # Пробуем подключиться
        client = _get_ssh_client(ip, port, username, private_key_str)
        
        # Проверяем, что соединение действительно работает
        transport = client.get_transport()
        if not transport or not transport.is_active():
            logger.error(f"Соединение с {ip}:{port} неактивно")
            return False, "Не удалось установить активное соединение"
            
        # Выполняем простую команду для проверки оболочки
        _, stdout, _ = client.exec_command('echo "Connection test"', timeout=10)
        if stdout.channel.recv_exit_status() != 0:
            logger.error(f"Тестовая команда на {ip}:{port} не выполнена")
            return False, "Не удалось выполнить тестовую команду"
            
        logger.info(f"Соединение с {ip}:{port} успешно проверено")
        return True, "Соединение успешно установлено и проверено"
        
    except paramiko.AuthenticationException as e:
        logger.error(f"Ошибка аутентификации на {ip}:{port}: {str(e)}")
        return False, f"Ошибка аутентификации: {str(e)}"
    except paramiko.SSHException as e:
        logger.error(f"Ошибка SSH на {ip}:{port}: {str(e)}")
        return False, f"Ошибка SSH: {str(e)}"
    except socket.timeout as e:
        logger.error(f"Таймаут подключения к {ip}:{port}")
        return False, f"Таймаут подключения к {ip}:{port}"
    except socket.error as e:
        logger.error(f"Сетевая ошибка при подключении к {ip}:{port}: {str(e)}")
        return False, f"Сетевая ошибка: {str(e)}"
    except Exception as e:
        logger.error(f"Неизвестная ошибка при тестировании соединения с {ip}:{port}: {str(e)}")
        return False, f"Неизвестная ошибка: {str(e)}"
    finally:
        if client:
            try:
                client.close()
            except Exception as e:
                logger.warning(f"Ошибка при закрытии SSH соединения: {e}")

def connect_with_password(host: str, port: int, username: str, password: str) -> Tuple[Optional[paramiko.SSHClient], Optional[str]]:
    """
    Подключается к серверу с использованием пароля.
    
    Args:
        host: Адрес хоста.
        port: Порт SSH.
        username: Имя пользователя.
        password: Пароль.
        
    Returns:
        Tuple[Optional[paramiko.SSHClient], Optional[str]]: (клиент, ошибка).
    """
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(CustomHostKeyPolicy())
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=15,
            allow_agent=False,
            look_for_keys=False
        )
        logger.info(f"Подключение с паролем к {host}:{port} успешно")
        return client, None
    except paramiko.AuthenticationException as e:
        logger.error(f"Ошибка аутентификации на {host}:{port}")
        return None, "Ошибка аутентификации: неверный пароль или имя пользователя."
    except paramiko.SSHException as e:
        logger.error(f"Ошибка SSH на {host}:{port}: {str(e)}")
        return None, f"Ошибка SSH: {str(e)}"
    except Exception as e:
        logger.error(f"Неизвестная ошибка при подключении к {host}:{port}: {str(e)}")
        return None, f"Неизвестная ошибка при подключении: {str(e)}"

def add_key_to_authorized_keys(host: str, port: int, username: str, password: str, public_key: str) -> Tuple[bool, str]:
    """
    Добавляет публичный ключ в authorized_keys на сервере, используя пароль.
    Использует SFTP для безопасного добавления ключа без проблем с экранированием.
    
    Args:
        host: Адрес хоста.
        port: Порт SSH.
        username: Имя пользователя.
        password: Пароль.
        public_key: Публичный ключ для добавления.
        
    Returns:
        Tuple[bool, str]: (успех, сообщение).
    """
    # Валидируем публичный ключ
    if not validate_ssh_public_key(public_key):
        logger.error("Некорректный формат публичного ключа")
        return False, "Некорректный формат публичного ключа"
    
    client, error = connect_with_password(host, port, username, password)
    if error:
        return False, error

    try:
        # 1. Создаем директорию .ssh если нужно
        stdin, stdout, stderr = client.exec_command('mkdir -p ~/.ssh && chmod 700 ~/.ssh')
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            error_msg = stderr.read().decode('utf-8').strip()
            logger.error(f"Ошибка при создании директории .ssh на {host}: {error_msg}")
            return False, f"Ошибка при создании директории: {error_msg}"
        
        # 2. Используем SFTP для безопасного добавления ключа
        sftp = client.open_sftp()
        
        # Проверяем, существует ли файл authorized_keys
        authorized_keys_path = '.ssh/authorized_keys'
        existing_keys = ""
        
        try:
            with sftp.open(authorized_keys_path, 'r') as f:
                existing_keys = f.read().decode('utf-8')
                # Проверяем, не существует ли уже такой ключ
                if public_key.strip() in existing_keys:
                    logger.info(f"Ключ уже существует на {host}")
                    sftp.close()
                    return True, "Ключ уже существует на сервере."
        except FileNotFoundError:
            logger.debug(f"Файл authorized_keys не найден на {host}, будет создан")
            existing_keys = ""
        
        # 3. Добавляем новый ключ через SFTP (безопасно, без экранирования)
        try:
            # Убедимся что ключ заканчивается на newline
            new_key_line = public_key.strip() + '\n'
            
            # Если файл пуст, просто пишем ключ, иначе добавляем в конец
            if existing_keys:
                # Убедимся что последний символ - newline перед добавлением
                if not existing_keys.endswith('\n'):
                    existing_keys += '\n'
                new_content = existing_keys + new_key_line
            else:
                new_content = new_key_line
            
            # Пишем обновленный файл
            with sftp.open(authorized_keys_path, 'w') as f:
                f.write(new_content.encode('utf-8'))
            
            # Устанавливаем правильные права доступа
            sftp.chmod(authorized_keys_path, 0o600)
            sftp.close()
            
            logger.info(f"Ключ успешно добавлен на {host} через SFTP")
            return True, "Ключ успешно добавлен."
            
        except Exception as e:
            sftp.close()
            logger.error(f"Ошибка при добавлении ключа через SFTP на {host}: {str(e)}")
            return False, f"Ошибка при добавлении ключа: {str(e)}"
            
    except Exception as e:
        logger.error(f"Ошибка при работе с сервером {host}: {str(e)}")
        return False, f"Ошибка при работе с сервером: {str(e)}"
    finally:
        if client:
            try:
                client.close()
            except Exception as e:
                logger.warning(f"Ошибка при закрытии соединения: {e}")

def revoke_key_from_server(
    server_ip: str,
    port: int,
    username: str,
    private_key_str: str,
    public_key: str
) -> Tuple[bool, str]:
    """
    Безопасно удаляет публичный ключ с сервера с созданием backup.
    
    Args:
        server_ip: IP-адрес сервера.
        port: Порт SSH.
        username: Имя пользователя.
        private_key_str: Приватный ключ.
        public_key: Публичный ключ для удаления.
        
    Returns:
        Tuple[bool, str]: (статус_операции, сообщение).
    """
    # Валидируем публичный ключ
    if not validate_ssh_public_key(public_key):
        logger.error("Некорректный формат публичного ключа при отзыве")
        return False, "Некорректный формат публичного ключа"
    
    client = None
    try:
        client = _get_ssh_client(server_ip, port, username, private_key_str)
        sftp = client.open_sftp()

        # Путь к файлу
        authorized_keys_path = '.ssh/authorized_keys'
        backup_path = '.ssh/authorized_keys.bak'

        # 1. Создаем backup перед изменением
        try:
            logger.info(f"Создание backup файла на {server_ip}")
            stdin, stdout, stderr = client.exec_command(f'cp {authorized_keys_path} {backup_path}')
            if stdout.channel.recv_exit_status() != 0:
                logger.warning(f"Не удалось создать backup на {server_ip}")
        except Exception as e:
            logger.warning(f"Ошибка при создании backup: {e}")

        # 2. Читаем файл
        try:
            with sftp.open(authorized_keys_path, 'r') as f:
                lines = f.readlines()
        except FileNotFoundError:
            logger.info(f"Файл authorized_keys не найден на {server_ip}")
            return True, "Файл authorized_keys не найден, ключ уже считается отозванным."

        # 3. Ищем и удаляем ключ
        original_line_count = len(lines)
        key_to_revoke_stripped = public_key.strip()
        lines = [line for line in lines if line.strip() != key_to_revoke_stripped]

        if len(lines) == original_line_count:
            logger.warning(f"Ключ не найден в authorized_keys на {server_ip}")
            return False, "Ключ не найден в файле authorized_keys."

        # 4. Перезаписываем файл
        try:
            with sftp.open(authorized_keys_path, 'w') as f:
                f.writelines(lines)
            logger.info(f"Ключ успешно отозван с {server_ip}")
        except Exception as e:
            logger.error(f"Ошибка при перезаписи authorized_keys на {server_ip}: {e}")
            # Пытаемся восстановить из backup
            try:
                stdin, stdout, stderr = client.exec_command(f'mv {backup_path} {authorized_keys_path}')
                logger.info(f"Файл восстановлен из backup на {server_ip}")
            except Exception as restore_error:
                logger.error(f"Не удалось восстановить из backup: {restore_error}")
            raise
        
        return True, "Ключ успешно отозван."

    except Exception as e:
        logger.error(f"Ошибка при отзыве ключа с {server_ip}: {str(e)}")
        return False, f"Ошибка при отзыве ключа: {str(e)}"
    finally:
        if client:
            try:
                client.close()
            except Exception as e:
                logger.warning(f"Ошибка при закрытии соединения: {e}")

def revoke_key_detailed(
    server_ip: str,
    ssh_port: int,
    username: str,
    private_key_str: str,
    public_key: str
) -> Tuple[bool, str, str]:
    """
    Удалить ключ с ДЕТАЛЬНОЙ диагностикой ошибок.
    
    Returns:
        (success: bool, message: str, error_code: str)
    """
    try:
        client = None
        try:
            client = _get_ssh_client(server_ip, ssh_port, username, private_key_str)
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            logger.error(f"Cannot connect to {server_ip}:{ssh_port}: {str(e)}")
            return False, f'Cannot connect to {server_ip}:{ssh_port}', 'CONNECTION_TIMEOUT'
        except paramiko.ssh_exception.AuthenticationException as e:
            logger.error(f"Authentication failed for user {username}: {str(e)}")
            return False, f'Authentication failed for user {username}', 'AUTH_FAILED'
        except socket.timeout:
            logger.error(f"Connection timeout to {server_ip}:{ssh_port}")
            return False, f'Connection timeout to {server_ip}:{ssh_port}', 'CONNECTION_TIMEOUT'
        except Exception as e:
            logger.error(f"Connection error: {str(e)}")
            return False, f'Connection error: {str(e)}', 'CONNECTION_ERROR'
        
        try:
            sftp = client.open_sftp()
            
            # Путь к файлу
            authorized_keys_path = '.ssh/authorized_keys'
            backup_path = '.ssh/authorized_keys.bak'
            
            # 1. Создаем backup перед изменением
            try:
                logger.info(f"Создание backup файла на {server_ip}")
                stdin, stdout, stderr = client.exec_command(f'cp {authorized_keys_path} {backup_path}')
                if stdout.channel.recv_exit_status() != 0:
                    logger.warning(f"Не удалось создать backup на {server_ip}")
            except Exception as e:
                logger.warning(f"Ошибка при создании backup: {e}")
            
            # 2. Читаем файл
            try:
                with sftp.open(authorized_keys_path, 'r') as f:
                    lines = f.readlines()
            except FileNotFoundError:
                logger.info(f"Файл authorized_keys не найден на {server_ip}")
                return True, "Файл authorized_keys не найден, ключ уже считается отозванным.", 'SUCCESS'
            
            # 3. Ищем и удаляем ключ
            original_line_count = len(lines)
            key_to_revoke_stripped = public_key.strip()
            lines = [line for line in lines if line.strip() != key_to_revoke_stripped]
            
            if len(lines) == original_line_count:
                logger.warning(f"Ключ не найден в authorized_keys на {server_ip}")
                return False, "Ключ не найден в файле authorized_keys.", 'KEY_NOT_FOUND'
            
            # 4. Перезаписываем файл
            try:
                with sftp.open(authorized_keys_path, 'w') as f:
                    f.writelines(lines)
                logger.info(f"Ключ успешно отозван с {server_ip}")
                return True, "Ключ успешно отозван.", 'SUCCESS'
            except Exception as e:
                logger.error(f"Ошибка при перезаписи authorized_keys на {server_ip}: {e}")
                # Пытаемся восстановить из backup
                try:
                    stdin, stdout, stderr = client.exec_command(f'mv {backup_path} {authorized_keys_path}')
                    logger.info(f"Файл восстановлен из backup на {server_ip}")
                except Exception as restore_error:
                    logger.error(f"Не удалось восстановить из backup: {restore_error}")
                return False, f"Ошибка при удалении ключа: {str(e)}", 'SSH_ERROR'
        
        except Exception as e:
            logger.error(f"SSH error during key revoke: {str(e)}")
            return False, f"SSH error: {str(e)}", 'SSH_ERROR'
        finally:
            if client:
                try:
                    client.close()
                except Exception as e:
                    logger.warning(f"Ошибка при закрытии соединения: {e}")
    
    except Exception as e:
        logger.error(f"Unexpected error in revoke_key_detailed: {str(e)}")
        return False, str(e), 'UNKNOWN_ERROR'

def deploy_key(ip: str, port: int, username: str, private_key_str: str, public_key_to_deploy: str, server=None) -> Tuple[bool, str]:
    """
    Развертывает публичный ключ на удаленном сервере.
    
    Args:
        ip: IP-адрес сервера.
        port: Порт SSH.
        username: Имя пользователя.
        private_key_str: Приватный ключ.
        public_key_to_deploy: Публичный ключ для развертывания.
        server: Объект Server из БД (опционально, для адаптивных алгоритмов).
        
    Returns:
        Tuple[bool, str]: (статус_операции, сообщение).
    """
    # Валидируем публичный ключ
    if not validate_ssh_public_key(public_key_to_deploy):
        logger.error("Некорректный формат публичного ключа при развертывании")
        return False, "Некорректный формат публичного ключа"
    
    client = None
    try:
        # Если передан объект server, используем адаптивные алгоритмы
        if server:
            logger.info(f"Развертывание ключа на {ip}:{port} с адаптивными алгоритмами (OpenSSH: {getattr(server, 'openssh_version', 'unknown')}, Legacy: {getattr(server, 'requires_legacy_ssh', False)})")
            key_file = None
            try:
                key_file = io.StringIO(private_key_str)
                if 'RSA' in private_key_str:
                    pkey = paramiko.RSAKey.from_private_key(key_file)
                elif 'PRIVATE KEY' in private_key_str:
                    pkey = paramiko.Ed25519Key.from_private_key(key_file)
                else:
                    raise paramiko.SSHException("Неподдерживаемый формат приватного ключа")
                
                client = connect_with_adaptive_algorithms(ip, port, username, pkey, server)
            finally:
                if key_file:
                    key_file.close()
        else:
            # Обычное подключение без адаптивных алгоритмов
            logger.info(f"Развертывание ключа на {ip}:{port} без адаптивных алгоритмов (информация о сервере недоступна)")
            client = _get_ssh_client(ip, port, username, private_key_str)
        
        # 1. Создаем директорию .ssh если нужно
        stdin, stdout, stderr = client.exec_command('mkdir -p ~/.ssh && chmod 700 ~/.ssh')
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            error = stderr.read().decode('utf-8')
            logger.error(f"Ошибка при создании директории .ssh на {ip}: {error}")
            return False, f"Ошибка при создании директории: {error}"
        
        # 2. Используем SFTP для безопасного добавления ключа
        sftp = client.open_sftp()
        
        # Проверяем, существует ли файл authorized_keys
        authorized_keys_path = '.ssh/authorized_keys'
        existing_keys = ""
        
        try:
            with sftp.open(authorized_keys_path, 'r') as f:
                existing_keys = f.read().decode('utf-8')
                # Проверяем, не существует ли уже такой ключ
                if public_key_to_deploy.strip() in existing_keys:
                    logger.info(f"Ключ уже существует на {ip}")
                    sftp.close()
                    return True, "Ключ уже существует на сервере."
        except FileNotFoundError:
            logger.debug(f"Файл authorized_keys не найден на {ip}, будет создан")
            existing_keys = ""
        
        # 3. Добавляем новый ключ через SFTP (безопасно, без экранирования)
        try:
            # Убедимся что ключ заканчивается на newline
            new_key_line = public_key_to_deploy.strip() + '\n'
            
            # Если файл пуст, просто пишем ключ, иначе добавляем в конец
            if existing_keys:
                # Убедимся что последний символ - newline перед добавлением
                if not existing_keys.endswith('\n'):
                    existing_keys += '\n'
                new_content = existing_keys + new_key_line
            else:
                new_content = new_key_line
            
            # Пишем обновленный файл
            with sftp.open(authorized_keys_path, 'w') as f:
                f.write(new_content.encode('utf-8'))
            
            # Устанавливаем правильные права доступа
            sftp.chmod(authorized_keys_path, 0o600)
            sftp.close()
            
            logger.info(f"Ключ успешно развернут на {ip} через SFTP")
            return True, "Ключ успешно развернут."
            
        except Exception as e:
            sftp.close()
            logger.error(f"Ошибка при добавлении ключа через SFTP на {ip}: {str(e)}")
            return False, f"Ошибка при добавлении ключа: {str(e)}"
            
    except Exception as e:
        logger.error(f"Ошибка при развертывании ключа на {ip}: {str(e)}")
        return False, str(e)
    finally:
        if client:
            try:
                client.close()
            except Exception as e:
                logger.warning(f"Ошибка при закрытии соединения: {e}")

def revoke_key_from_all_servers(public_key: str, all_servers: List, user_credentials: Dict) -> Dict:
    """
    Отзывает ключ со ВСЕХ серверов параллельно с таймаутом.
    
    Args:
        public_key: Публичный ключ для отзыва.
        all_servers: Список серверов.
        user_credentials: Словарь с credentials (encryption_key).
        
    Returns:
        Dict: Результаты операции с информацией об успехах и ошибках.
    """
    # Валидируем публичный ключ
    if not validate_ssh_public_key(public_key):
        logger.error("Некорректный формат публичного ключа при массовом отзыве")
        return {
            "success": [],
            "failed": [{"server_id": None, "error": "Некорректный формат публичного ключа"}],
            "total": len(all_servers),
            "revoked": 0
        }
    
    results = {
        "success": [],
        "failed": [],
        "total": len(all_servers),
        "revoked": 0
    }

    def revoke_task(server):
        """Задача для отзыва ключа с одного сервера."""
        try:
            access_key = server.access_key
            if not access_key:
                logger.warning(f"Ключ доступа для сервера {server.id} не найден")
                return server.id, False, "Ключ доступа для сервера не найден."
            
            try:
                private_key = decrypt_private_key(
                    access_key.private_key_encrypted, 
                    user_credentials['encryption_key']
                )
            except Exception as e:
                logger.error(f"Ошибка при дешифровке ключа для сервера {server.id}: {e}")
                return server.id, False, f"Ошибка при дешифровке ключа: {str(e)}"
            
            logger.info(f"Отзыв ключа с сервера {server.id} ({server.ip_address})")
            
            # Используем новую функцию revoke_key() с адаптивными алгоритмами
            # Передаем объект server для использования connect_with_adaptive_algorithms()
            result = revoke_key(
                server.ip_address,
                server.ssh_port,
                server.username,
                private_key,
                public_key,
                server  # Передаем объект server для адаптивных алгоритмов
            )
            return server.id, result['success'], result['message']
        except Exception as e:
            logger.error(f"Критическая ошибка при отзыве ключа с сервера {server.id}: {str(e)}")
            return server.id, False, f"Критическая ошибка: {str(e)}"

    # Используем ThreadPoolExecutor с таймаутом
    try:
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_server = {executor.submit(revoke_task, server): server for server in all_servers}
            
            # Таймаут на каждый поток: 60 секунд
            for future in as_completed(future_to_server, timeout=300):
                try:
                    server_id, success, message = future.result(timeout=60)
                    if success:
                        results["success"].append(server_id)
                        results["revoked"] += 1
                        logger.info(f"Ключ успешно отозван с сервера {server_id}")
                    else:
                        results["failed"].append({"server_id": server_id, "error": message})
                        logger.warning(f"Ошибка при отзыве ключа с сервера {server_id}: {message}")
                except FuturesTimeoutError:
                    server = future_to_server[future]
                    logger.error(f"Таймаут при отзыве ключа с сервера {server.id}")
                    results["failed"].append({"server_id": server.id, "error": "Таймаут операции"})
                except Exception as e:
                    server = future_to_server[future]
                    logger.error(f"Ошибка при обработке результата для сервера {server.id}: {e}")
                    results["failed"].append({"server_id": server.id, "error": str(e)})
    except FuturesTimeoutError:
        logger.error("Таймаут при выполнении всех операций отзыва")
        results["error"] = "Общий таймаут при выполнении операций"

    logger.info(f"Отзыв ключа завершен. Успешно: {results['revoked']}, Ошибок: {len(results['failed'])}")
    return results


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
        match = re.search(r'OpenSSH[_\s]+(\d+\.\d+)', version_string)
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


def initialize_server(ip: str, port: int, username: str, password: str) -> Dict:
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
    client = None
    try:
        logger.info(f"Инициализация сервера {ip}:{port} с пользователем {username}")
        
        # Подключаемся по паролю
        client, error = connect_with_password(ip, port, username, password)
        if error:
            logger.error(f"Ошибка подключения при инициализации {ip}: {error}")
            return {
                'success': False,
                'openssh_version': 'unknown',
                'requires_legacy_ssh': False,
                'message': error
            }
        
        # Выполняем ssh -V для получения версии
        try:
            stdin, stdout, stderr = client.exec_command('ssh -V', timeout=10)
            exit_status = stdout.channel.recv_exit_status()
            
            # ssh -V выводит в stderr
            version_output = stderr.read().decode('utf-8').strip()
            if not version_output:
                version_output = stdout.read().decode('utf-8').strip()
            
            logger.debug(f"Вывод ssh -V: {version_output}")
            
            # Парсим версию
            openssh_version = parse_openssh_version(version_output)
            
            # Определяем, требуется ли legacy SSH
            requires_legacy_ssh = False
            if openssh_version != "unknown":
                try:
                    # Парсим версию для сравнения
                    version_parts = openssh_version.split('.')
                    major = int(version_parts[0])
                    minor = int(version_parts[1]) if len(version_parts) > 1 else 0
                    
                    # Версии < 7.2 требуют legacy алгоритмов
                    if major < 7 or (major == 7 and minor < 2):
                        requires_legacy_ssh = True
                        logger.info(f"Сервер {ip} требует legacy SSH алгоритмов (версия {openssh_version})")
                except (ValueError, IndexError) as e:
                    logger.warning(f"Ошибка при парсинге версии {openssh_version}: {e}")
            
            logger.info(f"Инициализация сервера {ip} успешна. OpenSSH версия: {openssh_version}, Legacy: {requires_legacy_ssh}")
            
            return {
                'success': True,
                'openssh_version': openssh_version,
                'requires_legacy_ssh': requires_legacy_ssh,
                'message': f'Сервер инициализирован. OpenSSH версия: {openssh_version}'
            }
            
        except Exception as e:
            logger.error(f"Ошибка при выполнении ssh -V на {ip}: {e}")
            return {
                'success': False,
                'openssh_version': 'unknown',
                'requires_legacy_ssh': False,
                'message': f'Ошибка при определении версии OpenSSH: {str(e)}'
            }
            
    except Exception as e:
        logger.error(f"Ошибка при инициализации сервера {ip}: {e}")
        return {
            'success': False,
            'openssh_version': 'unknown',
            'requires_legacy_ssh': False,
            'message': f'Ошибка инициализации: {str(e)}'
        }
    finally:
        if client:
            try:
                client.close()
            except Exception as e:
                logger.warning(f"Ошибка при закрытии соединения: {e}")


def connect_with_adaptive_algorithms(ip: str, port: int, username: str, pkey, server_obj) -> Optional[paramiko.SSHClient]:
    """
    Подключается к серверу с адаптивными алгоритмами в зависимости от версии OpenSSH.
    
    Args:
        ip: IP-адрес сервера.
        port: Порт SSH.
        username: Имя пользователя.
        pkey: Приватный ключ Paramiko.
        server_obj: Объект Server из БД (содержит requires_legacy_ssh).
        
    Returns:
        Optional[paramiko.SSHClient]: SSH клиент или None при ошибке.
        
    Raises:
        Различные исключения Paramiko при ошибках подключения.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(CustomHostKeyPolicy())
    
    try:
        # Базовые параметры подключения
        connect_kwargs = {
            'hostname': ip,
            'port': port,
            'username': username,
            'pkey': pkey,
            'timeout': 15,
            'banner_timeout': 30,
            'auth_timeout': 20,
            'allow_agent': False,
            'look_for_keys': False
        }
        
        # Если требуется legacy SSH, отключаем новые алгоритмы
        if server_obj and hasattr(server_obj, 'requires_legacy_ssh') and server_obj.requires_legacy_ssh:
            logger.info(f"🔧 Использование legacy SSH алгоритмов для {ip}:{port} (OpenSSH версия: {getattr(server_obj, 'openssh_version', 'unknown')})")
            connect_kwargs['disabled_algorithms'] = {
                'pubkeys': ['rsa-sha2-512', 'rsa-sha2-256']
            }
        else:
            if server_obj:
                logger.info(f"✓ Использование стандартных SSH алгоритмов для {ip}:{port} (OpenSSH версия: {getattr(server_obj, 'openssh_version', 'unknown')})")
            else:
                logger.debug(f"Использование стандартных SSH алгоритмов для {ip}:{port} (информация о сервере недоступна)")
        
        logger.debug(f"Подключение к {ip}:{port} как {username} с параметрами: {connect_kwargs}")
        client.connect(**connect_kwargs)
        
        # Устанавливаем keepalive
        client.get_transport().set_keepalive(30)
        
        logger.info(f"SSH соединение успешно установлено с {ip}:{port}")
        return client
        
    except Exception as e:
        logger.error(f"Ошибка при подключении с адаптивными алгоритмами к {ip}:{port}: {str(e)}")
        raise


def deploy_key_with_password(ip: str, port: int, username: str, password: str, public_key: str) -> Dict:
    """
    Развертывает публичный ключ на сервере, подключаясь по паролю.
    Используется для первой инициализации сервера.
    
    Args:
        ip: IP-адрес сервера.
        port: Порт SSH.
        username: Имя пользователя.
        password: Пароль.
        public_key: Публичный ключ для развертывания.
        
    Returns:
        Dict: {
            'success': bool,
            'message': str
        }
    """
    # Валидируем публичный ключ
    if not validate_ssh_public_key(public_key):
        logger.error("Некорректный формат публичного ключа при развертывании по паролю")
        return {
            'success': False,
            'message': 'Некорректный формат публичного ключа'
        }
    
    client = None
    try:
        logger.info(f"Развертывание ключа на {ip}:{port} с паролем")
        
        # Подключаемся по паролю
        client, error = connect_with_password(ip, port, username, password)
        if error:
            logger.error(f"Ошибка подключения при развертывании ключа: {error}")
            return {
                'success': False,
                'message': error
            }
        
        # 1. Создаем директорию .ssh если нужно
        stdin, stdout, stderr = client.exec_command('mkdir -p ~/.ssh && chmod 700 ~/.ssh')
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            error_msg = stderr.read().decode('utf-8').strip()
            logger.error(f"Ошибка при создании директории .ssh на {ip}: {error_msg}")
            return {
                'success': False,
                'message': f'Ошибка при создании директории: {error_msg}'
            }
        
        # 2. Используем SFTP для безопасного добавления ключа
        sftp = client.open_sftp()
        
        # Проверяем, существует ли файл authorized_keys
        authorized_keys_path = '.ssh/authorized_keys'
        existing_keys = ""
        
        try:
            with sftp.open(authorized_keys_path, 'r') as f:
                existing_keys = f.read().decode('utf-8')
                # Проверяем, не существует ли уже такой ключ
                if public_key.strip() in existing_keys:
                    logger.info(f"Ключ уже существует на {ip}")
                    sftp.close()
                    return {
                        'success': True,
                        'message': 'Ключ уже существует на сервере.'
                    }
        except FileNotFoundError:
            logger.debug(f"Файл authorized_keys не найден на {ip}, будет создан")
            existing_keys = ""
        
        # 3. Добавляем новый ключ через SFTP (безопасно, без экранирования)
        try:
            # Убедимся что ключ заканчивается на newline
            new_key_line = public_key.strip() + '\n'
            
            # Если файл пуст, просто пишем ключ, иначе добавляем в конец
            if existing_keys:
                # Убедимся что последний символ - newline перед добавлением
                if not existing_keys.endswith('\n'):
                    existing_keys += '\n'
                new_content = existing_keys + new_key_line
            else:
                new_content = new_key_line
            
            # Пишем обновленный файл
            with sftp.open(authorized_keys_path, 'w') as f:
                f.write(new_content.encode('utf-8'))
            
            # Устанавливаем правильные права доступа
            sftp.chmod(authorized_keys_path, 0o600)
            sftp.close()
            
            logger.info(f"Ключ успешно развернут на {ip} через SFTP")
            return {
                'success': True,
                'message': 'Ключ успешно развернут.'
            }
            
        except Exception as e:
            sftp.close()
            logger.error(f"Ошибка при добавлении ключа через SFTP на {ip}: {str(e)}")
            return {
                'success': False,
                'message': f'Ошибка при добавлении ключа: {str(e)}'
            }
            
    except Exception as e:
        logger.error(f"Ошибка при развертывании ключа на {ip}: {str(e)}")
        return {
            'success': False,
            'message': f'Ошибка: {str(e)}'
        }
    finally:
        if client:
            try:
                client.close()
            except Exception as e:
                logger.warning(f"Ошибка при закрытии соединения: {e}")


def revoke_key(ip, port, username, private_key_str, public_key_to_revoke, server):
    """
    Удаляет публичный ключ с сервера с использованием адаптивных алгоритмов.
    
    Аргументы:
        ip: IP адрес сервера
        port: SSH порт
        username: Имя пользователя
        private_key_str: Приватный ключ в формате PEM
        public_key_to_revoke: Публичный ключ для удаления
        server: Объект Server из БД (содержит requires_legacy_ssh)
    
    Возвращает:
        Dict: {'success': bool, 'message': str}
    """
    client = None
    
    try:
        logger.info(f"Начинаем удаление ключа с сервера {ip}:{port} (OpenSSH: {getattr(server, 'openssh_version', 'unknown')}, Legacy: {getattr(server, 'requires_legacy_ssh', False)})")
        
        # Загружаем приватный ключ корректно
        key_file = io.StringIO(private_key_str)
        try:
            if 'RSA' in private_key_str:
                private_key = paramiko.RSAKey.from_private_key(key_file)
            elif 'PRIVATE KEY' in private_key_str:
                private_key = paramiko.Ed25519Key.from_private_key(key_file)
            else:
                raise paramiko.SSHException("Неподдерживаемый формат приватного ключа")
        finally:
            key_file.close()
        
        # Подключаемся с адаптивными алгоритмами
        client = connect_with_adaptive_algorithms(ip, port, username, private_key, server)
        
        if not client:
            logger.error(f"Не удалось подключиться к {ip}")
            return {
                'success': False,
                'message': f'Ошибка подключения к серверу {ip}'
            }
        
        # Используем SFTP для безопасного удаления ключа
        try:
            sftp = client.open_sftp()  # ✅ ПРАВИЛЬНЫЙ МЕТОД!
        except Exception as e:
            logger.error(f"Ошибка при открытии SFTP на {ip}: {str(e)}")
            return {
                'success': False,
                'message': f'Ошибка SFTP: {str(e)}'
            }
        
        try:
            # Скачиваем файл authorized_keys
            authorized_keys_path = '.ssh/authorized_keys'
            
            try:
                # Пытаемся скачать файл
                with io.BytesIO() as f:
                    sftp.getfo(authorized_keys_path, f)
                    f.seek(0)
                    content = f.read().decode('utf-8')
            except FileNotFoundError:
                logger.warning(f"Файл {authorized_keys_path} не найден на {ip}")
                sftp.close()
                return {
                    'success': False,
                    'message': f'Файл authorized_keys не найден'
                }
            
            # Разбиваем на строки и ищем ключ
            lines = content.strip().split('\n')
            key_found = False
            new_lines = []
            
            for line in lines:
                if line.strip() and public_key_to_revoke.strip() in line:
                    key_found = True
                    logger.info(f"Найден ключ для удаления на {ip}")
                    continue  # Пропускаем эту строку (удаляем)
                if line.strip():  # Сохраняем непустые строки
                    new_lines.append(line)
            
            if not key_found:
                logger.warning(f"Ключ не найден в authorized_keys на {ip}")
                sftp.close()
                return {
                    'success': False,
                    'message': 'Ключ не найден в authorized_keys'
                }
            
            # Загружаем обновленный файл обратно
            new_content = '\n'.join(new_lines)
            if new_content and not new_content.endswith('\n'):
                new_content += '\n'
            
            with io.BytesIO(new_content.encode('utf-8')) as f:
                sftp.putfo(f, authorized_keys_path)
            
            # Устанавливаем правильные права доступа
            sftp.chmod(authorized_keys_path, 0o600)
            
            logger.info(f"Ключ успешно удален с сервера {ip}")
            sftp.close()
            
            return {
                'success': True,
                'message': 'Ключ успешно удален с сервера'
            }
            
        except Exception as e:
            try:
                sftp.close()
            except:
                pass
            logger.error(f"Ошибка при удалении ключа на {ip}: {str(e)}")
            return {
                'success': False,
                'message': f'Ошибка при удалении ключа: {str(e)}'
            }
            
    except Exception as e:
        logger.error(f"Ошибка при удалении ключа с {ip}: {str(e)}")
        return {
            'success': False,
            'message': f'Ошибка: {str(e)}'
        }
    finally:
        if client:
            try:
                client.close()
            except Exception as e:
                logger.warning(f"Ошибка при закрытии соединения: {e}")

