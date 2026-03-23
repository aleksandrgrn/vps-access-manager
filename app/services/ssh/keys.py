import base64
import hashlib
import logging
import os
import subprocess
import tempfile
from typing import Optional, Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

# Настройка логирования
logger = logging.getLogger(__name__)


def get_secure_temp_dir() -> str:
    """Возвращает безопасную временную директорию для работы с секретами."""
    configured_temp_dir = os.environ.get("PPK_TEMP_DIR")
    if configured_temp_dir:
        if not os.path.isabs(configured_temp_dir):
            raise RuntimeError("PPK_TEMP_DIR должен быть абсолютным путём")
        if not os.path.isdir(configured_temp_dir) or not os.access(configured_temp_dir, os.W_OK):
            raise RuntimeError("PPK_TEMP_DIR недоступен для записи")

        return configured_temp_dir

    if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK):
        return "/dev/shm"

    raise RuntimeError("Безопасная временная директория недоступна на сервере")


def get_puttygen_path(puttygen_path: Optional[str] = None) -> str:
    """Возвращает путь до puttygen или вызывает ошибку, если он недоступен."""
    configured_path = puttygen_path or os.environ.get("PUTTYGEN_PATH") or "/usr/bin/puttygen"

    if os.path.isabs(configured_path):
        if os.path.isfile(configured_path) and os.access(configured_path, os.X_OK):
            return configured_path

    raise RuntimeError("Утилита puttygen недоступна на сервере")


def convert_private_key_to_ppk(private_key: str, puttygen_path: Optional[str] = None) -> bytes:
    """Конвертирует OpenSSH приватный ключ в формат PuTTY PPK."""
    if not private_key or not private_key.strip():
        raise ValueError("Приватный ключ пуст")

    resolved_puttygen_path = get_puttygen_path(puttygen_path)

    secure_temp_dir = get_secure_temp_dir()

    with tempfile.TemporaryDirectory(prefix="ppk_export_", dir=secure_temp_dir) as temp_dir:
        input_path = os.path.join(temp_dir, "input_key.pem")
        output_path = os.path.join(temp_dir, "output_key.ppk")

        with open(input_path, "w", encoding="utf-8") as input_file:
            input_file.write(private_key)
        os.chmod(input_path, 0o600)

        result = subprocess.run(
            [resolved_puttygen_path, input_path, "-o", output_path],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

        if result.returncode != 0:
            error_message = (
                result.stderr.strip() or "Не удалось сконвертировать ключ в формат PuTTY"
            )
            raise RuntimeError(error_message)

        if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
            raise RuntimeError("puttygen вернул пустой PPK файл")

        with open(output_path, "rb") as output_file:
            return output_file.read()


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
    logger.debug(f"Validating key: '{public_key}'")
    try:
        parts = public_key.strip().split()
        if len(parts) < 2:
            logger.warning(f"Validation failed: Too few parts ({len(parts)})")
            return False

        # Проверяем что это SSH ключ
        if parts[0] not in [
            "ssh-rsa",
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
        ]:
            logger.warning(f"Validation failed: Invalid key type: {parts[0]}")
            return False

        # Проверяем что base64 часть валидна
        try:
            base64.b64decode(parts[1])
            return True
        except Exception as e:
            logger.warning(f"Validation failed: Base64 decode failed: {e}")
            return False

    except Exception as e:
        logger.warning(f"Validation failed: Unexpected error: {e}")
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
