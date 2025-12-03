"""
Скрипт миграции для добавления категорий серверов.

Выполняет:
1. Создание таблицы server_categories
2. Создание таблицы server_category_association
3. Предзаполнение категориями: Production, Staging, Internal, External
"""

import sys
from pathlib import Path

# Добавляем корневую директорию проекта в путь
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from app import create_app, db  # noqa: E402
from app.models import ServerCategory  # noqa: E402


def upgrade():
    """Создание таблиц и предзаполнение данными."""
    app = create_app()

    with app.app_context():
        # Создаем таблицы
        db.create_all()

        # Предзаполненные категории
        default_categories = [
            {"name": "Production", "color": "#dc3545"},  # Красный
            {"name": "Staging", "color": "#ffc107"},  # Желтый
            {"name": "Internal", "color": "#0d6efd"},  # Синий
            {"name": "External", "color": "#198754"},  # Зеленый
        ]

        # Добавляем категории, если они еще не существуют
        for cat_data in default_categories:
            existing = ServerCategory.query.filter_by(name=cat_data["name"]).first()
            if not existing:
                category = ServerCategory(**cat_data)
                db.session.add(category)
                print(f"✓ Добавлена категория: {cat_data['name']}")
            else:
                print(f"⊘ Категория уже существует: {cat_data['name']}")

        db.session.commit()
        print("\n✅ Миграция успешно выполнена!")


def downgrade():
    """Откат миграции (удаление таблиц и данных)."""
    app = create_app()

    with app.app_context():
        # Удаляем все категории
        ServerCategory.query.delete()

        # Удаляем таблицы
        db.session.execute(db.text("DROP TABLE IF EXISTS server_category_association"))
        db.session.execute(db.text("DROP TABLE IF EXISTS server_categories"))

        db.session.commit()
        print("✅ Откат миграции выполнен!")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "downgrade":
        print("⚠️  Выполняется откат миграции...")
        downgrade()
    else:
        print("▶️  Выполняется миграция...")
        upgrade()
