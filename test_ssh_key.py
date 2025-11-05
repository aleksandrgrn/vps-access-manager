#!/usr/bin/env python3
"""
Диагностика SSH ключа для сервера
Проверяет что ключ валидный и может подключиться
"""
import os
import io
from dotenv import load_dotenv
from app import app, db, SSHKey, Server
import paramiko

load_dotenv()

def test_key_connection(key_name: str, server_name: str):
    """Тестировать подключение с ключом к серверу"""
    
    with app.app_context():
        # 1. Получить ключ из БД
        ssh_key = SSHKey.query.filter_by(name=key_name).first()
        if not ssh_key:
            print(f"❌ Ключ '{key_name}' не найден в БД")
            return
        
        # 2. Получить сервер из БД
        server = Server.query.filter_by(name=server_name).first()
        if not server:
            print(f"❌ Сервер '{server_name}' не найден в БД")
            return
        
        print(f"✓ Ключ найден: {key_name}")
        print(f"✓ Сервер найден: {server_name} ({server.ip_address}:{server.ssh_port})")
        print()
        
        # 3. Расшифровать приватный ключ
        encryption_key = os.environ.get('ENCRYPTION_KEY')
        try:
            from ssh_manager import decrypt_private_key
            private_key = decrypt_private_key(ssh_key.private_key_encrypted, encryption_key)
            print("✓ Приватный ключ успешно расшифрован")
            print(f"  Первые 50 символов: {private_key[:50]}...")
        except Exception as e:
            print(f"❌ Ошибка расшифровки: {e}")
            return
        
        print()
        
        # 4. Проверить формат приватного ключа
        try:
            pkey = paramiko.RSAKey.from_private_key(io.StringIO(private_key))
            print("✓ Формат приватного ключа ВАЛИДНЫЙ (RSA)")
            print(f"  Длина: {pkey.get_bits()} бит")
        except Exception as e:
            print(f"❌ Ошибка формата ключа: {e}")
            return
        
        print()
        
        # 5. Проверить что публичные ключи совпадают
        try:
            from ssh_manager import get_public_key_from_private
            derived_public = get_public_key_from_private(private_key)
            if derived_public.strip() == ssh_key.public_key.strip():
                print("✓ Публичный ключ СОВПАДАЕТ с приватным")
            else:
                print("❌ Публичный ключ НЕ совпадает!")
                print(f"  В БД: {ssh_key.public_key[:50]}...")
                print(f"  От приватного: {derived_public[:50]}...")
        except Exception as e:
            print(f"⚠ Не удалось проверить совпадение: {e}")
        
        print()
        
        # 6. Попытаться подключиться к серверу
        print(f"Попытка подключиться к {server.ip_address}:{server.ssh_port} как {server.username}...")
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            client.connect(
                server.ip_address,
                port=server.ssh_port,
                username=server.username,
                pkey=pkey,
                timeout=5,
                look_for_keys=False,
                allow_agent=False
            )
            
            print("✅ ПОДКЛЮЧЕНИЕ УСПЕШНО!")
            
            # Выполнить тестовую команду
            stdin, stdout, stderr = client.exec_command('echo "SSH works!"')
            result = stdout.read().decode().strip()
            print(f"✓ Команда выполнена: {result}")
            
            client.close()
            
        except paramiko.ssh_exception.AuthenticationException as e:
            print(f"❌ ОШИБКА АУТЕНТИФИКАЦИИ: {e}")
            print("  Возможно публичный ключ не добавлен в authorized_keys на сервере")
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            print(f"❌ ОШИБКА ПОДКЛЮЧЕНИЯ: {e}")
            print("  Проверьте IP адрес, порт и доступность сервера")
        except Exception as e:
            print(f"❌ ОШИБКА: {e}")

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 3:
        print("Использование: python test_ssh_key.py <имя_ключа> <имя_сервера>")
        print("Пример: python test_ssh_key.py root_rif-terminal.ru rif-terminal.ru")
        sys.exit(1)
    
    key_name = sys.argv[1]
    server_name = sys.argv[2]
    
    test_key_connection(key_name, server_name)
