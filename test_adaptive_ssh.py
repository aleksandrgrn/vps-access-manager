"""
Тесты для адаптивного подключения SSH с автоинициализацией серверов.

Этот скрипт содержит примеры тестирования новых функций.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import ssh_manager
import logging

# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def test_parse_openssh_version():
    """Тест парсинга версии OpenSSH"""
    print("\n" + "="*60)
    print("ТЕСТ 1: Парсинг версии OpenSSH")
    print("="*60)
    
    test_cases = [
        ("OpenSSH_5.3p1 OpenSSL 0.9.8e", "5.3"),
        ("OpenSSH_6.6.1p1 Ubuntu 2ubuntu2.13", "6.6"),
        ("OpenSSH_7.4p1 Debian-10+deb9u7", "7.4"),
        ("OpenSSH_8.0p1 Ubuntu 8.0p1-6ubuntu0.1", "8.0"),
        ("OpenSSH 7.2", "7.2"),
        ("Invalid version string", "unknown"),
    ]
    
    for version_string, expected in test_cases:
        result = ssh_manager.parse_openssh_version(version_string)
        status = "✓" if result == expected else "✗"
        print(f"{status} Input: {version_string}")
        print(f"  Expected: {expected}, Got: {result}")


def test_legacy_ssh_detection():
    """Тест определения необходимости legacy SSH"""
    print("\n" + "="*60)
    print("ТЕСТ 2: Определение необходимости legacy SSH")
    print("="*60)
    
    test_cases = [
        ("5.3", True, "CentOS 6"),
        ("5.9", True, "Ubuntu 12.04"),
        ("6.0", True, "Debian 7"),
        ("6.6", True, "CentOS 7 (старая версия)"),
        ("7.0", True, "OpenSSH 7.0"),
        ("7.1", True, "OpenSSH 7.1"),
        ("7.2", False, "OpenSSH 7.2 (граница)"),
        ("7.4", False, "CentOS 8"),
        ("8.0", False, "Ubuntu 20.04"),
        ("unknown", False, "Неизвестная версия (безопасное значение)"),
    ]
    
    for version, expected_legacy, description in test_cases:
        # Имитируем логику из initialize_server
        requires_legacy_ssh = False
        if version != "unknown":
            try:
                version_parts = version.split('.')
                major = int(version_parts[0])
                minor = int(version_parts[1]) if len(version_parts) > 1 else 0
                
                if major < 7 or (major == 7 and minor < 2):
                    requires_legacy_ssh = True
            except (ValueError, IndexError):
                pass
        
        status = "✓" if requires_legacy_ssh == expected_legacy else "✗"
        print(f"{status} {description}")
        print(f"  Version: {version}, Legacy: {requires_legacy_ssh}, Expected: {expected_legacy}")


def test_connect_with_adaptive_algorithms():
    """
    Тест функции connect_with_adaptive_algorithms.
    
    ПРИМЕЧАНИЕ: Этот тест требует реального SSH сервера для подключения.
    Используйте только для интеграционного тестирования.
    """
    print("\n" + "="*60)
    print("ТЕСТ 3: Подключение с адаптивными алгоритмами")
    print("="*60)
    print("ПРОПУЩЕН: Требует реального SSH сервера")
    print("Для тестирования используйте реальный сервер")


def test_initialize_server():
    """
    Тест функции initialize_server.
    
    ПРИМЕЧАНИЕ: Этот тест требует реального SSH сервера для подключения.
    Используйте только для интеграционного тестирования.
    """
    print("\n" + "="*60)
    print("ТЕСТ 4: Инициализация сервера")
    print("="*60)
    print("ПРОПУЩЕН: Требует реального SSH сервера")
    print("Для тестирования используйте реальный сервер")
    print("\nПример использования:")
    print("""
    result = ssh_manager.initialize_server(
        ip='192.168.1.100',
        port=22,
        username='root',
        password='your_password'
    )
    
    if result['success']:
        print(f"OpenSSH версия: {result['openssh_version']}")
        print(f"Требуется legacy SSH: {result['requires_legacy_ssh']}")
    else:
        print(f"Ошибка: {result['message']}")
    """)


def test_deploy_key_with_password():
    """
    Тест функции deploy_key_with_password.
    
    ПРИМЕЧАНИЕ: Этот тест требует реального SSH сервера для подключения.
    Используйте только для интеграционного тестирования.
    """
    print("\n" + "="*60)
    print("ТЕСТ 5: Развертывание ключа по паролю")
    print("="*60)
    print("ПРОПУЩЕН: Требует реального SSH сервера")
    print("Для тестирования используйте реальный сервер")
    print("\nПример использования:")
    print("""
    # Сгенерируем тестовый ключ
    private_key, public_key = ssh_manager.generate_ssh_key('rsa')
    
    result = ssh_manager.deploy_key_with_password(
        ip='192.168.1.100',
        port=22,
        username='root',
        password='your_password',
        public_key=public_key
    )
    
    if result['success']:
        print(f"Ключ успешно развернут: {result['message']}")
    else:
        print(f"Ошибка: {result['message']}")
    """)


def run_all_tests():
    """Запустить все тесты"""
    print("\n" + "="*60)
    print("ТЕСТИРОВАНИЕ АДАПТИВНОГО SSH")
    print("="*60)
    
    test_parse_openssh_version()
    test_legacy_ssh_detection()
    test_connect_with_adaptive_algorithms()
    test_initialize_server()
    test_deploy_key_with_password()
    
    print("\n" + "="*60)
    print("ТЕСТИРОВАНИЕ ЗАВЕРШЕНО")
    print("="*60)
    print("\nДля интеграционного тестирования используйте реальный сервер:")
    print("1. Запустите Flask приложение")
    print("2. Откройте веб-интерфейс")
    print("3. Добавьте новый сервер через форму")
    print("4. Проверьте логи для информации о версии OpenSSH")


if __name__ == '__main__':
    run_all_tests()
