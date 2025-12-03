"""
Category Routes

Маршруты для управления категориями серверов.
"""

import logging
from typing import Any, Dict, Tuple

from flask import Blueprint, jsonify, request
from flask_login import login_required

from app import db
from app.models import ServerCategory

bp = Blueprint("categories", __name__)
logger = logging.getLogger(__name__)


@bp.route("/categories", methods=["GET"])
@login_required
def get_categories() -> Tuple[Dict[str, Any], int]:
    """
    Получение списка всех категорий.

    Returns:
        JSON со списком категорий: [{id, name, color, count}]
    """
    try:
        categories = ServerCategory.query.all()
        result = []
        for category in categories:
            # Считаем количество серверов пользователя в этой категории
            # Note: ServerCategory.servers - это dynamic relationship, но
            # нам нужно отфильтровать только серверы текущего пользователя,
            # если категории общие. Если категории общие для всех, то просто count.
            # В модели ServerCategory нет user_id, значит категории общие?
            # Или подразумевается, что они общие.
            # В задаче не сказано про user_id в ServerCategory.
            # Предположим, что категории глобальные или мы просто считаем все серверы.
            # Но лучше фильтровать по user_id, если бы он был.
            # Посмотрим модель ServerCategory еще раз.
            # ServerCategory(id, name, color, created_at). Нет user_id.
            # Значит категории общие.

            # Однако, пользователь должен видеть count только СВОИХ серверов в этой категории?
            # Или вообще всех? Обычно в таких системах категории свои у каждого юзера,
            # но если модели нет user_id, то они общие.
            # Давайте посчитаем просто количество серверов в категории.

            # Но постойте, если я добавлю сервер в категорию "Production",
            # и другой юзер добавит, то count будет 2.
            # Если это SaaS, то это плохо. Если single-tenant
            # (VPS Manager для одного админа), то ок.
            # Судя по коду (UserMixin, login_required), это может быть многопользовательская.
            # Но раз в модели нет user_id, делаем как есть.

            # Оптимизация: count() на query
            server_count = category.servers.count()

            result.append(
                {
                    "id": category.id,
                    "name": category.name,
                    "color": category.color,
                    "count": server_count,
                }
            )

        return jsonify(result), 200

    except Exception as e:
        logger.error(f"[GET_CATEGORIES_ERROR] {str(e)}")
        return jsonify({"success": False, "message": f"Ошибка: {str(e)}"}), 500


@bp.route("/categories", methods=["POST"])
@login_required
def create_category() -> Tuple[Dict[str, Any], int]:
    """
    Создание новой категории.

    Input:
        JSON {name, color}

    Returns:
        JSON с созданной категорией
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "Нет данных"}), 400

        name = data.get("name")
        color = data.get("color", "#6c757d")

        if not name:
            return jsonify({"success": False, "message": "Имя категории обязательно"}), 400

        # Проверка уникальности имени
        if ServerCategory.query.filter_by(name=name).first():
            return (
                jsonify({"success": False, "message": "Категория с таким именем уже существует"}),
                400,
            )

        new_category = ServerCategory(name=name, color=color)
        db.session.add(new_category)
        db.session.commit()

        return (
            jsonify(
                {
                    "success": True,
                    "category": {
                        "id": new_category.id,
                        "name": new_category.name,
                        "color": new_category.color,
                    },
                }
            ),
            201,
        )

    except Exception as e:
        db.session.rollback()
        logger.error(f"[CREATE_CATEGORY_ERROR] {str(e)}")
        return jsonify({"success": False, "message": f"Ошибка: {str(e)}"}), 500


@bp.route("/categories/<int:category_id>", methods=["DELETE"])
@login_required
def delete_category(category_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Удаление категории.

    Args:
        category_id: ID категории

    Returns:
        JSON с результатом
    """
    category = ServerCategory.query.get_or_404(category_id)

    try:
        # Так как нет user_id, любой залогиненный может удалить любую категорию?
        # В реальном приложении нужна проверка прав.
        # Но пока делаем по ТЗ.

        db.session.delete(category)
        db.session.commit()

        return jsonify({"success": True, "message": "Категория удалена"}), 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"[DELETE_CATEGORY_ERROR] {str(e)}")
        return jsonify({"success": False, "message": f"Ошибка: {str(e)}"}), 500
