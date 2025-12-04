"""
Добавление поля description в таблицу ssh_keys
"""

import os
import sqlite3


def migrate():
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "instance", "vps_manager.db")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # Проверка, есть ли уже колонка
        cursor.execute("PRAGMA table_info(ssh_keys)")
        columns = [col[1] for col in cursor.fetchall()]

        if "description" not in columns:
            cursor.execute("ALTER TABLE ssh_keys ADD COLUMN description TEXT")
            conn.commit()
            print("✅ Колонка 'description' добавлена в таблицу ssh_keys")
        else:
            print("ℹ️  Колонка 'description' уже существует")
    except Exception as e:
        print(f"❌ Ошибка миграции: {e}")
        conn.rollback()
    finally:
        conn.close()


if __name__ == "__main__":
    migrate()
