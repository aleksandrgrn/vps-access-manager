import base64
import hashlib
import logging
from typing import Optional, Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

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
                public_exponent=65537, key_size=4096, backend=default_backend()
            )
        elif key_type == "ed25519":
            key = ed25519.Ed25519PrivateKey.generate()
        else:
            raise ValueError("Неподдерживаемый тип ключа. Используйте 'rsa' или 'ed25519'.")

        private_key_pem = key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.OpenSSH,
            crypto_serialization.NoEncryption(),
        )

        public_key_ssh = key.public_key().public_bytes(
            crypto_serialization.Encoding.OpenSSH,
            crypto_serialization.PublicFormat.OpenSSH,
        )

        logger.info(f"SSH ключ успешно сгенерирован ({key_type})")
        return private_key_pem.decode("utf-8"), public_key_ssh.decode("utf-8")

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
        md5_hash = hashlib.md5(
            key_data, usedforsecurity=False
        ).hexdigest()  # nosec: SSH fingerprint only
        fingerprint = ":".join(a + b for a, b in zip(md5_hash[::2], md5_hash[1::2]))

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
        if parts[0] not in [
            "ssh-rsa",
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
        ]:
            return False

        # Проверяем что base64 часть валидна
        try:
            base64.b64decode(parts[1])
            return True
        except Exception:
            return False

    except Exception:
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

        f = Fernet(encryption_key.encode("utf-8"))
        encrypted_key = f.encrypt(private_key.encode("utf-8"))

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

        f = Fernet(encryption_key.encode("utf-8"))
        decrypted_key = f.decrypt(encrypted_key)

        logger.debug("Приватный ключ успешно дешифрован")
        return decrypted_key.decode("utf-8")

    except Exception as e:
        logger.error(f"Ошибка при дешифровке ключа: {e}")
        raise
