"""
Key Service - обёртка над ssh_manager с полной обработкой ошибок

Все SSH операции с детальным логированием и обработкой ошибок.
ЯКОРЬ #1: БД обновляется ТОЛЬКО после успешной SSH операции!
"""
import os
import logging
from typing import Dict, Any, List, Optional
from cryptography.fernet import Fernet, InvalidToken
import ssh_manager
from app.models import Server, SSHKey

logger = logging.getLogger(__name__)


def decrypt_access_key(access_key: 'SSHKey') -> Dict[str, Any]:
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
    logger.info(f"[DECRYPT_START] Начало расшифровки access_key (key_id={access_key.id if access_key else None})")
    
    # ЭТАП 1: Валидация входных данных
    if not access_key:
        logger.error("[DECRYPT_ERROR] access_key=None")
        return {
            'success': False,
            'message': 'Ключ доступа для сервера не найден',
            'error_type': 'missing_access_key'
        }
    
    # ЭТАП 2: Проверка ENCRYPTION_KEY
    encryption_key = os.environ.get('ENCRYPTION_KEY')
    if not encryption_key:
        logger.error("[DECRYPT_ERROR] ENCRYPTION_KEY не установлен в переменных окружения")
        return {
            'success': False,
            'message': 'ENCRYPTION_KEY не установлен на сервере',
            'error_type': 'missing_encryption_key'
        }
    
    # ЭТАП 3: Проверка зашифрованного ключа
    if not access_key.private_key_encrypted:
        logger.error(f"[DECRYPT_ERROR] private_key_encrypted пуст для ключа {access_key.id}")
        return {
            'success': False,
            'message': 'Приватный ключ не найден в БД',
            'error_type': 'missing_private_key'
        }
    
    # ЭТАП 4: Попытка расшифровки
    try:
        logger.debug(f"[DECRYPT_ATTEMPT] Расшифровка ключа {access_key.id}")
        private_key = ssh_manager.decrypt_private_key(
            access_key.private_key_encrypted,
            encryption_key
        )
        
        # ЭТАП 5: Валидация результата
        if not private_key or len(private_key) < 100:
            logger.error(f"[DECRYPT_ERROR_VALIDATION] Результат расшифровки пуст или слишком короткий (len={len(private_key) if private_key else 0})")
            return {
                'success': False,
                'message': 'Расшифрованный ключ невалиден',
                'error_type': 'invalid_decrypted_key'
            }
        
        logger.info(f"[DECRYPT_SUCCESS] Ключ {access_key.id} успешно расшифрован")
        return {
            'success': True,
            'private_key': private_key
        }
    
    except InvalidToken:
        logger.error(f"[DECRYPT_ERROR_VALIDATION] InvalidToken - неверный ENCRYPTION_KEY или повреждённые данные")
        return {
            'success': False,
            'message': 'Неверный ключ шифрования или повреждённые данные',
            'error_type': 'invalid_encryption_key'
        }
    
    except ValueError as ve:
        logger.error(f"[DECRYPT_ERROR_EXCEPTION] ValueError: {str(ve)}")
        return {
            'success': False,
            'message': f'Ошибка валидации при расшифровке: {str(ve)}',
            'error_type': 'decryption_value_error'
        }
    
    except Exception as e:
        logger.error(f"[DECRYPT_ERROR_EXCEPTION] Неожиданная ошибка: {str(e)}")
        return {
            'success': False,
            'message': f'Критическая ошибка расшифровки: {str(e)}',
            'error_type': 'decryption_critical_error'
        }


def revoke_key_from_single_server(
    server: Server,
    private_key: str,
    key_to_revoke: SSHKey
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
    logger.info(f"[REVOKE_SSH_START] Отзыв ключа {key_to_revoke.name} с сервера {server.name} ({server.ip_address})")
    
    try:
        # Вызов SSH операции с передачей server объекта
        success, message, error_type = ssh_manager.revoke_key_detailed(
            server_ip=server.ip_address,
            ssh_port=server.ssh_port,
            username=server.username,
            private_key_str=private_key,
            public_key=key_to_revoke.public_key,
            server=server  # ← ДОБАВЛЕНО для поддержки legacy SSH
        )
        
        if success:
            logger.info(f"[REVOKE_SSH_SUCCESS] Ключ успешно удалён с {server.name}")
            return {
                'success': True,
                'message': f'Ключ успешно отозван с сервера {server.name}'
            }
        else:
            logger.warning(f"[REVOKE_SSH_FAILED] Не удалось удалить ключ: {message} (error_type={error_type})")
            return {
                'success': False,
                'message': message,
                'details': f'Сервер: {server.name} ({server.ip_address}:{server.ssh_port})',
                'error_type': error_type or 'ssh_revoke_failed'
            }
    
    except Exception as e:
        logger.error(f"[REVOKE_SSH_EXCEPTION] Исключение при отзыве: {str(e)}")
        return {
            'success': False,
            'message': f'SSH ошибка: {str(e)}',
            'details': f'Не удалось подключиться к {server.ip_address}:{server.ssh_port}',
            'error_type': 'ssh_exception'
        }


def revoke_key_from_all_servers(
    key: SSHKey,
    servers: List[Server],
    access_keys: Dict[int, SSHKey]
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
    
    results = {
        'success_count': 0,
        'failed_count': 0,
        'results': []
    }
    
    for server in servers:
        access_key = access_keys.get(server.id)
        if not access_key:
            logger.warning(f"[REVOKE_BULK_SKIP] Нет access_key для сервера {server.name}")
            results['failed_count'] += 1
            results['results'].append({
                'server_name': server.name,
                'server_ip': server.ip_address,
                'success': False,
                'message': 'Нет ключа доступа для сервера'
            })
            continue
        
        # Расшифровка
        decrypt_result = decrypt_access_key(access_key)
        if not decrypt_result['success']:
            logger.warning(f"[REVOKE_BULK_DECRYPT_FAIL] Не удалось расшифровать ключ для {server.name}")
            results['failed_count'] += 1
            results['results'].append({
                'server_name': server.name,
                'server_ip': server.ip_address,
                'success': False,
                'message': decrypt_result['message']
            })
            continue
        
        # SSH отзыв
        revoke_result = revoke_key_from_single_server(
            server,
            decrypt_result['private_key'],
            key
        )
        
        if revoke_result['success']:
            results['success_count'] += 1
        else:
            results['failed_count'] += 1
        
        results['results'].append({
            'server_name': server.name,
            'server_ip': server.ip_address,
            'success': revoke_result['success'],
            'message': revoke_result['message']
        })
    
    logger.info(f"[REVOKE_BULK_COMPLETE] Успешно: {results['success_count']}, Ошибок: {results['failed_count']}")
    return results


def deploy_key_to_server(
    server: Server,
    private_key: str,
    key_to_deploy: SSHKey
) -> Dict[str, Any]:
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
        success, message = ssh_manager.deploy_key(
            ip=server.ip_address,
            port=server.ssh_port,
            username=server.username,
            private_key_str=private_key,
            public_key_to_deploy=key_to_deploy.public_key,
            server=server
        )
        
        if success:
            logger.info(f"[DEPLOY_SUCCESS] Ключ развёрнут на {server.name}")
            return {
                'success': True,
                'message': f'Ключ успешно развёрнут на {server.name}'
            }
        else:
            logger.warning(f"[DEPLOY_FAILED] {message}")
            return {
                'success': False,
                'message': message,
                'error_type': 'deploy_failed'
            }
    
    except Exception as e:
        logger.error(f"[DEPLOY_EXCEPTION] {str(e)}")
        return {
            'success': False,
            'message': f'Ошибка развёртывания: {str(e)}',
            'error_type': 'deploy_exception'
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
        ssh_format = 'legacy'
    else:
        logger.info(f"[TEST_CONNECTION] Сервер {server.name} использует modern SSH (OpenSSH >= 7.2)")
        ssh_format = 'modern'
    
    try:
        success, message = ssh_manager.test_connection(
            ip=server.ip_address,
            port=server.ssh_port,
            username=server.username,
            private_key_str=private_key,
            server=server  # Передаем объект server для адаптивных алгоритмов
        )
        
        if success:
            logger.info(f"[TEST_CONNECTION_SUCCESS] Соединение с {server.name} успешно установлено ({ssh_format})")
            return {
                'success': True,
                'message': f'SSH соединение успешно (формат: {ssh_format})',
                'ssh_format': ssh_format
            }
        else:
            logger.warning(f"[TEST_CONNECTION_FAILED] Ошибка соединения с {server.name}: {message}")
            return {
                'success': False,
                'message': message,
                'ssh_format': ssh_format
            }
    
    except Exception as e:
        logger.error(f"[TEST_CONNECTION_EXCEPTION] Исключение при тестировании {server.name}: {str(e)}")
        return {
            'success': False,
            'message': f'Ошибка тестирования: {str(e)}',
            'ssh_format': ssh_format
        }
