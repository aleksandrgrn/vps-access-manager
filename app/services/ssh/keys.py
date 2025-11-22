"""
SSH Key Management Module

Handles generation, encryption, decryption, and validation of SSH keys.
"""

import base64
import io
import logging
from typing import Optional, Tuple

import paramiko
from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)


def generate_ssh_key(key_type: str = "rsa") -> Tuple[str, str]:
    """
    Генерирует пару SSH ключей (приватный и публичный).

    Args:
        key_type: Тип ключа ('rsa' или 'ed25519').

    Returns:
        Tuple[str, str]: (private_key_pem, public_key_ssh)
    """
    try:
        if key_type == "rsa":
            key = paramiko.RSAKey.generate(2048)

            out = io.StringIO()
            key.write_private_key(out)
            private_key_pem = out.getvalue()
            public_key_ssh = f"{key.get_name()} {key.get_base64()}"

        elif key_type == "ed25519":
            # Paramiko < 3.5 может не иметь Ed25519Key.generate
            # Используем cryptography напрямую
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ed25519

            key = ed25519.Ed25519PrivateKey.generate()

            # Приватный ключ в OpenSSH формате
            private_bytes = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=serialization.NoEncryption(),
            )
            private_key_pem = private_bytes.decode("utf-8")

            # Публичный ключ в OpenSSH формате
            public_bytes = key.public_key().public_bytes(
                encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH
            )
            public_key_ssh = public_bytes.decode("utf-8")

        else:
            raise ValueError(f"Неподдерживаемый тип ключа: {key_type}")

        return private_key_pem, public_key_ssh
    except Exception as e:
        logger.error(f"Ошибка при генерации ключа: {e}")
        raise


def get_fingerprint(public_key: str) -> Optional[str]:
    """
    Вычисляет fingerprint публичного ключа (SHA256).

    Args:
        public_key: Строка публичного ключа (например "ssh-rsa AAA...").

    Returns:
        str: Fingerprint в формате "SHA256:..." или None при ошибке.
    """
    try:
        parts = public_key.split()
        if len(parts) < 2:
            return None

        key_type = parts[0]
        key_data = parts[1]

        key_bytes = base64.b64decode(key_data)

        if key_type == "ssh-rsa":
            key = paramiko.RSAKey(data=key_bytes)
        elif key_type == "ssh-ed25519":
            key = paramiko.Ed25519Key(data=key_bytes)
        else:
            # Попытка определить тип автоматически
            if "rsa" in key_type:
                key = paramiko.RSAKey(data=key_bytes)
            elif "ed25519" in key_type:
                key = paramiko.Ed25519Key(data=key_bytes)
            else:
                return None

        # Получаем fingerprint в байтах
        key.get_fingerprint()

        # Конвертируем в hex (MD5 стиль, старый) или base64 (SHA256, новый)
        # Paramiko get_fingerprint возвращает MD5 хэш для старых версий или просто байты
        # Но лучше использовать стандартный формат SHA256
        import hashlib

        fp_sha256 = hashlib.sha256(key_bytes).digest()
        fp_str = "SHA256:" + base64.b64encode(fp_sha256).decode("utf-8").rstrip("=")

        return fp_str
    except Exception as e:
        logger.error(f"Ошибка при вычислении fingerprint: {e}")
        return None


def validate_ssh_public_key(public_key: str) -> bool:
    """
    Проверяет валидность формата публичного SSH ключа.

    Args:
        public_key: Строка публичного ключа.

    Returns:
        bool: True если ключ валиден, иначе False.
    """
    try:
        parts = public_key.split()
        if len(parts) < 2:
            return False

        key_type = parts[0]
        key_data = parts[1]

        key_bytes = base64.b64decode(key_data)

        if key_type == "ssh-rsa":
            paramiko.RSAKey(data=key_bytes)
        elif key_type == "ssh-ed25519":
            paramiko.Ed25519Key(data=key_bytes)
        else:
            return False

        return True
    except Exception:
        return False


def encrypt_private_key(private_key: str, encryption_key: str) -> bytes:
    """
    Шифрует приватный ключ с использованием Fernet.

    Args:
        private_key: Приватный ключ (строка).
        encryption_key: Ключ шифрования (Fernet key).

    Returns:
        bytes: Зашифрованный ключ.
    """
    f = Fernet(encryption_key.encode())
    return f.encrypt(private_key.encode())


def decrypt_private_key(encrypted_private_key: bytes, encryption_key: str) -> str:
    """
    Расшифровывает приватный ключ.

    Args:
        encrypted_private_key: Зашифрованный ключ (bytes).
        encryption_key: Ключ шифрования.

    Returns:
        str: Расшифрованный приватный ключ.

    Raises:
        InvalidToken: Если ключ не подходит.
    """
    f = Fernet(encryption_key.encode())
    # Если вдруг пришла строка (legacy), кодируем в байты
    if isinstance(encrypted_private_key, str):
        encrypted_private_key = encrypted_private_key.encode()
    return f.decrypt(encrypted_private_key).decode()


def parse_openssh_version(version_output: str) -> str:
    """
    Парсит версию OpenSSH из вывода команды ssh -V.
    Пример вывода: OpenSSH_8.9p1 Ubuntu-3ubuntu0.1, OpenSSL 3.0.2 15 Mar 2022
    Возвращает: 8.9p1
    """
    try:
        # OpenSSH_8.9p1 Ubuntu-3ubuntu0.1, ...
        parts = version_output.split()
        if not parts:
            return "unknown"

        # OpenSSH_8.9p1
        ssh_part = parts[0]
        if "_" in ssh_part:
            version = ssh_part.split("_")[1]
            # Удаляем запятую если есть
            version = version.rstrip(",")
            return version
        return "unknown"
    except Exception:
        return "unknown"
