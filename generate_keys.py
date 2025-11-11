#!/usr/bin/env python3
"""
Генератор ключей для .env файла VPS Manager
"""
import secrets
from cryptography.fernet import Fernet

def generate_env_keys():
    """Генерирует ключи для .env файла"""
    
    secret_key = secrets.token_hex(32)
    encryption_key = Fernet.generate_key().decode()
    
    env_content = f"""# VPS Manager Environment Configuration
# Generated automatically

SECRET_KEY={secret_key}
ENCRYPTION_KEY={encryption_key}
FLASK_ENV=production
DATABASE_URL=sqlite:///vps_manager.db
"""
    
    print("=" * 70)
    print("🔑 КЛЮЧИ ДЛЯ .ENV ФАЙЛА (PRODUCTION)")
    print("=" * 70)
    print(env_content)
    print("=" * 70)
    print("⚠️  ВАЖНО:")
    print("1. Скопируйте эти ключи в файл .env")
    print("2. НИКОГДА не коммитьте .env в Git")
    print("3. Сохраните backup ключей в безопасное место")
    print("4. При потере ENCRYPTION_KEY невозможно расшифровать SSH-ключи!")
    print("=" * 70)
    
    # Опционально: сохранить в файл
    save = input("\n💾 Сохранить в файл .env? (y/n): ").strip().lower()
    if save == 'y':
        with open('.env', 'w') as f:
            f.write(env_content)
        print("✅ Файл .env создан!")
    else:
        print("ℹ️  Скопируйте ключи вручную")

if __name__ == "__main__":
    generate_env_keys()
